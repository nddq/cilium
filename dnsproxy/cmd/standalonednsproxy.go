package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/dnsproxy/pkg/maps"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/dnsproxy/metrics"
	sdpDNS "github.com/cilium/cilium/dnsproxy/pkg/dns"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
	Timeout:             5 * time.Second,  // wait 1 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

var serverPort = 40045 // default port for cilium-agent

type StandaloneDNSProxyArgs struct {
	logger                 *slog.Logger
	address                string
	port                   uint16
	ipv4                   bool
	ipv6                   bool
	enableDNSCompression   bool
	maxRestoreDNSIps       int
	concurrencyLimit       int
	concurrencyGracePeriod time.Duration
	toFqdnServerPort       uint16
	enableL7Proxy          bool
}

type StandaloneDNSProxy struct {
	DNSProxy   *dnsproxy.DNSProxy
	Client     pb.AzureFQDNDataClient
	connection *grpc.ClientConn

	ciliumAgentConnection   *trigger.Trigger
	dnsRulesStream          pb.AzureFQDNData_SubscribeToDNSRulesClient
	fqdnMappingStream       pb.AzureFQDNData_UpdateMappingsClient
	fqdnMappingResponseChan lock.Map[uint32, chan *pb.Result]

	cancelSubscribeToDNSRules context.CancelFunc
	log                       *slog.Logger
}

func NewStandaloneDNSProxy(logger *slog.Logger) *StandaloneDNSProxy {
	return &StandaloneDNSProxy{
		log: logger,
	}
}

func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	sdp.DNSProxy.Cleanup()

	err := sdp.closeConnection()
	if err != nil {
		sdp.log.Error("Failed to close connection", logfields.Error, err)
		return err
	}
	return nil
}

// StartStandaloneDNSProxy starts a standalone DNS proxy
//   - The first step is to read the file system to recover the DNS entries
//   - The second step is initialize the Regex for the DNS entries
//   - The third step is to start the DNS proxy
//   - the fourth step is to connect to the FQDN service(hosted by the agent)
func (sdp *StandaloneDNSProxy) StartCiliumAgentConnection() error {
	var err error
	defer func() {
		if err != nil {
			sdp.log.Error("Failed to start cilium agent connection", logfields.Error, err)
			sdp.closeConnection()
			metrics.CiliumAgentConnection.WithLabelValues(err.Error()).Inc()
			sdp.ciliumAgentConnection.TriggerWithReason("Failed to start cilium agent connection")
		}
	}()

	if sdp.connection == nil {
		sdp.log.Error("Connection is nil", logfields.Error, err)
		return fmt.Errorf("connection is nil")
	}

	// Create the client
	sdp.Client = pb.NewAzureFQDNDataClient(sdp.connection)

	sdp.log.Debug("Successfully created client for Cilium agent")

	// Create the subscription stream
	if sdp.dnsRulesStream == nil {
		err = sdp.createSubscriptionStream(context.Background())
		if err != nil {
			sdp.log.Error("Failed to create subscription stream", logfields.Error, err)
			return err
		}
	}

	// Create the FQDN mapping stream
	if sdp.fqdnMappingStream == nil {
		st, err := sdp.Client.UpdateMappings(context.Background())
		if err != nil {
			sdp.log.Error("Failed to create FQDN mapping stream", logfields.Error, err)
			return err
		}
		sdp.fqdnMappingStream = st
	}

	return nil
}

func (sdp *StandaloneDNSProxy) ConnectToCiliumAgent() error {
	var err error
	defer func() {
		if err != nil {
			sdp.log.Error("Failed to connect to cilium agent", logfields.Error, err)
			metrics.CiliumAgentConnection.WithLabelValues(err.Error()).Inc()
			sdp.ciliumAgentConnection.TriggerWithReason("Failed to connect to cilium agent")
		}
	}()

	if sdp.connection != nil {
		return nil
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithKeepaliveParams(kacp))

	address := fmt.Sprintf("localhost:%d", serverPort)

	sdp.log.Info("Connecting to server", logfields.Address, address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5) // 5 seconds timeout
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		sdp.log.Error("Failed to connect to server at address", logfields.Error, err, logfields.Address, address)
		return err
	}
	sdp.log.Info("Connected to server", logfields.Address, address)
	sdp.connection = conn

	return nil // Successfully reconnected
}

func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy(args *StandaloneDNSProxyArgs) error {

	// Initialize the local identity cache
	maps.Init()
	dnsproxyConfig := dnsproxy.DNSProxyConfig{
		Logger:                 args.logger,
		Address:                args.address,
		IPv4:                   args.ipv4,
		IPv6:                   args.ipv6,
		EnableDNSCompression:   args.enableDNSCompression,
		MaxRestoreDNSIPs:       args.maxRestoreDNSIps,
		ConcurrencyLimit:       args.concurrencyLimit,
		ConcurrencyGracePeriod: args.concurrencyGracePeriod,
	}

	sdp.DNSProxy = dnsproxy.NewDNSProxy(dnsproxyConfig, sdp, sdp.LookupEPByIP, sdp.NotifyOnDNSMsg)

	if err := sdp.DNSProxy.Listen(args.port); err != nil {
		return fmt.Errorf("failed to start DNS proxy: %w", err)
	}

	// Override the default server port if specified
	if args.toFqdnServerPort != 0 {
		serverPort = int(args.toFqdnServerPort)
	}

	if !args.enableL7Proxy {
		sdp.log.Info("L7 Proxy is disabled")
		return nil
	}
	sdp.log.Info("DNS Proxy started", logfields.Address, args.address, logfields.Port, args.port)

	// Create the cilium agent connection trigger
	err := sdp.createCiliumAgentConnectionTrigger()
	if err != nil {
		sdp.log.Error("Failed to create the trigger for connecting to Cilium agent", logfields.Error, err)
		return err
	}

	// trigger the cilium agent connection
	sdp.ciliumAgentConnection.TriggerWithReason("Start standalone DNS proxy")
	return nil
}

// createCiliumAgentConnectionTrigger creates a trigger to connect to the cilium agent
// 1. It tries to connect to the cilium agent
// 2. If the connection is successful, it tries to start the grpc streams
// 3. If the streams are started, it tries to subscribe to the DNS rules as go routine
func (sdp *StandaloneDNSProxy) createCiliumAgentConnectionTrigger() error {
	var err error
	sdp.ciliumAgentConnection, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "start-cilium-agent-connection",
		MinInterval: 5 * time.Second,
		TriggerFunc: func(reasons []string) {
			defer func() {
				if r := recover(); r != nil {
					sdp.log.Error("Recovered from panic in trigger function", logfields.Error, r)
					metrics.CiliumAgentConnection.WithLabelValues("panic").Inc()
				}
			}()
			sdp.log.Info("Triggering cilium agent connection", logfields.Reasons, reasons)
			// 1. Try creating the connection to the cilium agent
			err := sdp.ConnectToCiliumAgent()
			if err != nil {
				sdp.log.Error("Failed to connect to cilium agent", logfields.Error, err)
				return
			}

			// 2. Try starting the cilium agent connection
			err = sdp.StartCiliumAgentConnection()
			if err != nil {
				sdp.log.Error("Failed to start cilium agent connection")
				return
			}

			ctx, cancel := context.WithCancel(context.Background())
			sdp.cancelSubscribeToDNSRules = cancel // Store the cancel function for later use

			// 3. Try to subscribe to the DNS rules
			go sdp.subscribeToDNSRules(ctx)

			// 4. Receive the responses from the cilium agent
			go sdp.receiveResponses()
		},
	})
	if err != nil {
		sdp.log.Error("Failed to create trigger", logfields.Error, err)
		return err // Return the error after logging
	}
	return nil
}

func (sdp *StandaloneDNSProxy) LookupEPByIP(ip netip.Addr) (endPt *endpoint.Endpoint, isHost bool, err error) {
	sdp.log.Debug("LookupEPByIP", logfields.IPAddr, ip.String())
	ipAddr := net.ParseIP(ip.String())
	endpointMetadata, err := maps.GetEndpointMetadata(ipAddr)
	if err != nil {
		sdp.log.Error("Failed to get endpoint metadata for IP", logfields.IPAddr, ip.String())
		return nil, false, err
	}

	endpt := &endpoint.Endpoint{
		ID: endpointMetadata.LxcID,
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(endpointMetadata.SecID),
		},
	}
	endpt.SetIsHost(endpointMetadata.IsHost())
	sdp.log.Debug("Endpoint found", logfields.Endpoint, endpt)
	return endpt, endpointMetadata.IsHost(), nil
}

func (sdp *StandaloneDNSProxy) LookupByIdentity(nid identity.NumericIdentity) []string {
	return nil
}

func (sdp *StandaloneDNSProxy) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	sdp.log.Debug("LookupSecIDByIP", logfields.IPAddr, ip.String())
	secId, err := maps.GetIdentity(ip)
	if err != nil {
		sdp.log.Error("Failed to get identity for IP", logfields.IPAddr, ip.String())
		return ipcache.Identity{}, false
	}

	sdp.log.Debug("Identity found", logfields.Identity, secId)
	return ipcache.Identity{
		ID:     identity.NumericIdentity(secId.SecurityIdentity),
		Source: source.Local, // Local source means the identity is from the local agent
	}, true
}

func (s *StandaloneDNSProxy) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	s.log.Debug("Received DNS message", logfields.Message, msg)

	if stat.Err != nil {
		metrics.DNSRequestNotResolved.WithLabelValues(stat.Err.Error()).Inc()
	}

	qname, responseIPs, TTL, CNAMEs, rcode, answerTypes, qtypes, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		s.log.Error("cannot extract DNS message details", logfields.Error, err)
		return err
	}

	var ips [][]byte
	for _, i := range responseIPs {
		s.log.Debug("qname mapping", logfields.Name, qname, logfields.IPAddr, i.String())
		ips = append(ips, []byte(i.String()))
	}

	// Split the IP:Port to get the IP
	clientIp, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		s.log.Error("Failed to split IP:Port")
		return err
	}

	metrics := formatMetricsData(stat, epIPPort, serverID, serverAddr, msg.Response, CNAMEs, qtypes, answerTypes, allowed, protocol)
	message := pb.AzureFQDNMapping{
		FQDN:         qname,
		IPS:          ips,
		TTL:          TTL,
		ClientIp:     []byte(clientIp),
		ResponseCode: uint32(rcode),
		Metrics:      &metrics,
		RequestId:    uint32(msg.Id),
	}

	err = s.SendFqdnMapping(&message)
	if err != nil {
		s.log.Error("Failed to send FQDN Mapping message", logfields.Error, err)
		return err
	}
	return nil
}

// formatMetricsData formats the metrics data to be sent to the Cilium Agent
func formatMetricsData(stat *dnsproxy.ProxyRequestContext, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, response bool, CNAMEs []string, qtypes, answerTypes []uint16, allowed bool, protocol string) pb.MetricsData {
	statErr := ""
	if stat.Err != nil {
		statErr = stat.Err.Error()
	}

	return pb.MetricsData{
		ProcessingStats: &pb.ProcessingStats{
			Err:        statErr,
			DataSource: string(stat.DataSource),
		},
		DnsResponseData: &pb.DNSResponseData{
			Response:    response,
			Cnames:      CNAMEs,
			Qtypes:      convertToUint32Slice(qtypes),
			AnswerTimes: convertToUint32Slice(answerTypes),
		},
		EndpointIpPort: epIPPort,
		ServerAddr:     serverAddr.Addr().String(),
		ServerIdentity: uint32(serverID),
		Protocol:       protocol,
		Allowed:        allowed,
	}
}

func convertToUint32Slice(input []uint16) []uint32 {
	output := make([]uint32, len(input))
	for i, v := range input {
		output[i] = uint32(v)
	}
	return output
}

func (sdp *StandaloneDNSProxy) SendFqdnMapping(message *pb.AzureFQDNMapping) error {
	var err error
	defer func() {
		if err != nil {
			sdp.closeFqdnMappingStream()
			sdp.log.Error("Failed to send FQDN mapping")
			if err == io.EOF || status.Code(err) == codes.Unavailable {
				sdp.closeConnection()
				sdp.ciliumAgentConnection.TriggerWithReason("Received EOF from FQDN mapping stream")
				sdp.log.Error("Received EOF from FQDN mapping stream")
			} else {
				sdp.ciliumAgentConnection.TriggerWithReason("Failed to send FQDN mapping")
				sdp.log.Error("Failed to send FQDN mapping", logfields.Error, err)
			}
			metrics.FQDNMappingSync.WithLabelValues(err.Error()).Inc()
		}
	}()

	if sdp.fqdnMappingStream == nil {
		sdp.log.Error("FQDN mapping stream is nil")
		return fmt.Errorf("FQDN mapping stream is nil")
	}

	// store the response channel with the key as dns message id
	responseChan := make(chan *pb.Result, 1)
	sdp.fqdnMappingResponseChan.Store(message.GetRequestId(), responseChan)

	err = sdp.fqdnMappingStream.Send(message)
	if err != nil {
		sdp.log.Error("Failed to send FQDN Mapping message", logfields.Error, err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Wait for the response from the cilium agent
	// 1. If the response is received, log the response
	// 2. If the context is cancelled, log the timeout
	// 3. If there is an error, log the error
	select {
	case <-ctx.Done():
		sdp.log.Warn("Timeout waiting for result from FQDN mapping stream for request id", logfields.ID, message.GetRequestId())
	case result := <-responseChan:
		sdp.log.Debug("Received result from FQDN mapping stream", logfields.Result, result)
	}

	return nil
}

func (sdp *StandaloneDNSProxy) receiveResponses() error {
	var err error
	defer func() {
		if err != nil {
			sdp.closeFqdnMappingStream()
			if err == io.EOF || status.Code(err) == codes.Unavailable {
				sdp.closeConnection()
				sdp.ciliumAgentConnection.TriggerWithReason("Received EOF from FQDN mapping stream")
				sdp.log.Error("Received EOF from FQDN mapping stream")
			} else {
				sdp.ciliumAgentConnection.TriggerWithReason("Failed to receive FQDN mapping")
				sdp.log.Error("Failed to receive FQDN mapping", logfields.Error, err)
			}
		}
	}()

	for {
		if sdp.fqdnMappingStream == nil {
			sdp.log.Error("FQDN mapping stream is nil")
			return fmt.Errorf("FQDN mapping stream is nil")
		}

		response, err := sdp.fqdnMappingStream.Recv()
		if err != nil {
			if err == io.EOF || status.Code(err) == codes.Unavailable {
				sdp.log.Error("fqdn mapping stream closed", logfields.Error, err)
				return fmt.Errorf("fqdn mapping stream closed")
			}
			sdp.log.Error("Failed to receive response", logfields.Error, err)
			return fmt.Errorf("failed to receive response")
		}

		// Extract the dns message id from the response
		dnsMsgID := response.GetRequestId()

		// Get the response channel from the map
		responseChan, ok := sdp.fqdnMappingResponseChan.Load(dnsMsgID)
		if !ok {
			sdp.log.Error("Response channel not found for dns message id", logfields.ID, dnsMsgID)
		} else {
			// Send the response to the response channel or else timeout after 2 seconds
			ticker := time.NewTicker(2 * time.Second)
			select {
			case responseChan <- response:
				// Successfully sent the response
			case <-ticker.C:
				sdp.log.Warn("Timeout sending response for dns message id", logfields.ID, dnsMsgID)
			}
			ticker.Stop()
		}
		// Delete the response channel from the map
		sdp.fqdnMappingResponseChan.Delete(dnsMsgID)
		sdp.log.Debug("Deleted response channel for dns message id", logfields.ID, dnsMsgID)

	}
}

// subscribeToDNSRules subscribes to the DNS rules
// 1. Tries to get the stream connected
// 2. If the stream is connected, it waits for the DNS rules to be received
func (sdp *StandaloneDNSProxy) subscribeToDNSRules(ctx context.Context) error {
	var err error
	defer func() {
		if err != nil {
			sdp.closeDNSRuleStream()
			switch status.Code(err) {
			case codes.Unavailable:
				sdp.closeConnection()
				sdp.ciliumAgentConnection.TriggerWithReason("DNS server unavailable")
			default:
				if err == io.EOF {
					sdp.closeConnection()
					sdp.ciliumAgentConnection.TriggerWithReason("Received EOF from DNS rules stream")
					sdp.log.Error("Received EOF from DNS rules stream")
				} else {
					sdp.ciliumAgentConnection.TriggerWithReason("Failed to subscribe to DNS rules")
					sdp.log.Error("Failed to subscribe to DNS rules", logfields.Error, err)
				}
			}
			metrics.RetrieveDNSRules.WithLabelValues(err.Error()).Inc()
		}
		sdp.cancelSubscribeToDNSRules()
	}()

	for {
		select {
		case <-ctx.Done():
			// Context was cancelled, exit goroutine
			sdp.log.Info("Stopping subscription to DNS rules")
			return nil
		default:
			sdp.log.Debug("Waiting for DNS rules")
			newRules, recvErr := sdp.dnsRulesStream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF || status.Code(recvErr) == codes.Unavailable {
					sdp.log.Error("DNS rules stream closed", logfields.Error, recvErr)
					err = recvErr
					return err
				}
				sdp.log.Error("Failed to receive DNS rules", logfields.Error, recvErr)
				err = recvErr // Set the outer err for the deferred function to handle.
				return err
			}
			sdp.log.Debug("Received DNS rule", logfields.Rules, newRules)
			sdp.UpdateDNSRules(newRules)
		}
	}
}

func (sdp *StandaloneDNSProxy) closeFqdnMappingStream() {
	if sdp.fqdnMappingStream != nil {
		err := sdp.fqdnMappingStream.CloseSend()
		if err != nil {
			sdp.log.Error("Failed to close Fqdn mapping stream", logfields.Error, err)
		}
		sdp.fqdnMappingStream = nil
	}
}

func (sdp *StandaloneDNSProxy) closeDNSRuleStream() {
	if sdp.dnsRulesStream != nil {
		err := sdp.dnsRulesStream.CloseSend()
		if err != nil {
			sdp.log.Error("Failed to close DNS rules stream", logfields.Error, err)
		}
		sdp.dnsRulesStream = nil
	}
}

func (sdp *StandaloneDNSProxy) closeConnection() error {
	if sdp.connection != nil {
		err := sdp.connection.Close()
		if err != nil {
			sdp.log.Error("Failed to close connection", logfields.Error, err)
			return err
		}
		sdp.connection = nil
	}
	return nil
}

func (sdp *StandaloneDNSProxy) createSubscriptionStream(ctx context.Context) error {
	if sdp.Client == nil {
		sdp.log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}

	stream, err := sdp.Client.SubscribeToDNSRules(ctx, &pb.Request{})
	if err != nil {
		sdp.log.Error("Failed to subscribe to DNS rules", logfields.Error, err)
		metrics.RetrieveDNSRules.WithLabelValues(err.Error()).Inc()
		return err
	}
	sdp.dnsRulesStream = stream
	return nil
}

func (sdp *StandaloneDNSProxy) UpdateDNSRules(newRules *pb.DNSPolicyRules) {
	// Format the DNS rules to DNS proxy rules
	l7DataMap := make(policy.L7DataMap)
	for _, rule := range newRules.GetRules() {
		var portRuleDNS []api.PortRuleDNS
		r := rule.GetPortRules()
		for _, r := range r {
			portRuleDNS = append(portRuleDNS, api.PortRuleDNS{
				MatchName:    r.GetMatchName(),
				MatchPattern: r.GetMatchPattern(),
			})
		}

		cacheSelector := sdpDNS.SelectorRules{
			Selection:      rule.GetSelections(),
			Rules:          portRuleDNS,
			Key:            rule.GetSelectorString(),
			MetadataLabels: labels.ParseLabelArray(strings.Join(rule.GetMatchLabels(), ",")),
		}
		l7DataMap[&cacheSelector] = &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{DNS: portRuleDNS},
		}
	}

	protocol := u8proto.UDP
	destPortProto := restore.MakeV2PortProto(uint16(newRules.GetPort()), protocol).ToV1()
	if newRules.GetProtocol() != 0 {
		protocol = u8proto.U8proto(newRules.GetProtocol())
		destPortProto = restore.MakeV2PortProto(uint16(newRules.GetPort()), protocol)
	}
	sdp.DNSProxy.UpdateAllowed(newRules.GetEndpointId(), destPortProto, l7DataMap)
}
