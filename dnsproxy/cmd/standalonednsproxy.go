package cmd

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/dnsproxy/pkg/maps"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

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
	Logger                 *slog.Logger
	Address                string
	Port                   uint16
	IPv4                   bool
	IPv6                   bool
	EnableDNSCompression   bool
	MaxRestoreDNSIps       int
	ConcurrencyLimit       int
	ConcurrencyGracePeriod time.Duration
	ToFqdnServerPort       uint16
	EnableL7Proxy          bool
}

type StandaloneDNSProxy struct {
	DNSProxy          *dnsproxy.DNSProxy
	Client            pb.FQDNDataClient
	connection        *grpc.ClientConn
	connectionWatcher *ConnectionWatcher

	ciliumAgentConnection    *trigger.Trigger
	fqdnMappingStreamWrapper *FqdnMappingStreamWrapper
	dnsRulesStreamWrapper    *DNSRulesStreamWrapper

	ciliumAgentConnectionContext     context.Context
	cancelCiliumAgentConnectionUsers context.CancelFunc
	log                              *slog.Logger
}

// uniqueID converts the request ID and domain name into a unique uint32 value using FNV-1a.
func uniqueID(reqID int32, domain string) uint32 {
	h := fnv.New32a()
	// Generate a random number to combine with the request ID and domain.
	randNum := rand.Int32N(math.MaxInt32)
	// Combine the request ID, domain, and random number using a colon as delimiter.
	idStr := strconv.Itoa(int(reqID)) + ":" + domain + ":" + strconv.Itoa(int(randNum))
	h.Write([]byte(idStr))
	return h.Sum32()
}

func NewStandaloneDNSProxy(logger *slog.Logger) *StandaloneDNSProxy {
	return &StandaloneDNSProxy{
		log: logger,
	}
}

func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	isConnected.Store(false)
	sdp.DNSProxy.Cleanup()

	err := sdp.closeConnection()
	if err != nil {
		sdp.log.Error("Failed to close connection", logfields.Error, err)
		return err
	}
	return nil
}

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

	sdp.log.Info("Starting cilium agent connection")
	if sdp.connection == nil {
		sdp.log.Error("Connection is nil", logfields.Error, err)
		return fmt.Errorf("connection is nil")
	}

	// Create the client
	sdp.Client = pb.NewFQDNDataClient(sdp.connection)

	sdp.log.Debug("Successfully created client for Cilium agent")

	// Create the subscription stream
	if sdp.dnsRulesStreamWrapper == nil {
		sdp.dnsRulesStreamWrapper, err = NewDNSRulesStreamWrapper(
			sdp.Client,
			sdp.connectionWatcher.connectionLock,
			sdp.ciliumAgentConnection.TriggerWithReason,
			sdp.ciliumAgentConnectionContext,
			sdp.UpdateDNSRules,
			sdp.log,
		)

		if err != nil {
			sdp.log.Error("Failed to create DNS rules stream wrapper", logfields.Error, err)
			return err
		}

		sdp.log.Info("DNS rules stream wrapper created")
	}

	// Create the DNS rules stream
	err = sdp.dnsRulesStreamWrapper.CreateDNSRulesStreamIfNil(sdp.Client, sdp.ciliumAgentConnectionContext, false)
	if err != nil {
		return err
	}
	sdp.log.Info("DNS rules stream created")

	if sdp.fqdnMappingStreamWrapper == nil {
		sdp.fqdnMappingStreamWrapper, err = NewFqdnMappingStreamWrapper(
			sdp.Client,
			sdp.connectionWatcher.connectionLock,
			sdp.ciliumAgentConnection.TriggerWithReason,
			sdp.ciliumAgentConnectionContext,
			sdp.log,
		)
		if err != nil {
			sdp.log.Error("Failed to create FQDN mapping stream", logfields.Error, err)
			return err
		}

		sdp.log.Info("FQDN mapping stream wrapper created")
	}

	// Create the FQDN Mapping stream
	err = sdp.fqdnMappingStreamWrapper.CreateFqdnMappingStreamIfNil(sdp.Client, sdp.ciliumAgentConnectionContext, false)
	if err != nil {
		return err
	}

	sdp.log.Info("Cilium agent connection created successfully")

	isConnected.Store(true)
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

	ctx, cancel := context.WithCancel(context.Background())
	sdp.cancelCiliumAgentConnectionUsers = cancel
	sdp.ciliumAgentConnectionContext = ctx

	if sdp.connectionWatcher == nil {
		sdp.connectionWatcher = NewConnectionWatcher(
			sdp.cancelCiliumAgentConnectionUsers,
			sdp.closeConnection,
			sdp.log,
		)
	} else {
		sdp.connectionWatcher.UpdateCancelUsersFunction(sdp.cancelCiliumAgentConnectionUsers)
	}

	// Create the connection to the cilium agent

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithKeepaliveParams(kacp))

	address := fmt.Sprintf("localhost:%d", serverPort)

	sdp.log.Info("Connecting to server", logfields.Address, address)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*5) // 5 seconds timeout
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

// StartStandaloneDNSProxy starts a standalone DNS proxy
// It initializes the local identity cache and starts the DNS proxy.
// It also creates a trigger to connect to the cilium agent and starts the connection.
// The trigger is responsible for creating the connection and starting the grpc streams.
func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy(args *StandaloneDNSProxyArgs) error {

	// Initialize the local identity cache
	maps.Init()
	dnsproxyConfig := dnsproxy.DNSProxyConfig{
		Logger:                 args.Logger,
		Address:                args.Address,
		IPv4:                   args.IPv4,
		IPv6:                   args.IPv6,
		EnableDNSCompression:   args.EnableDNSCompression,
		MaxRestoreDNSIPs:       args.MaxRestoreDNSIps,
		ConcurrencyLimit:       args.ConcurrencyLimit,
		ConcurrencyGracePeriod: args.ConcurrencyGracePeriod,
	}

	sdp.DNSProxy = dnsproxy.NewDNSProxy(dnsproxyConfig, sdp, sdp.LookupEPByIP, sdp.NotifyOnDNSMsg)

	if err := sdp.DNSProxy.Listen(args.Port); err != nil {
		metrics.ProxyBootstrapError.WithLabelValues(err.Error()).Inc()
		return fmt.Errorf("failed to start DNS proxy: %w", err)
	}

	// Override the default server port if specified
	if args.ToFqdnServerPort != 0 {
		serverPort = int(args.ToFqdnServerPort)
	}

	if !args.EnableL7Proxy {
		sdp.log.Info("L7 Proxy is disabled")
		// In case of ACNS enabled with just obs as true, we start the daemonset with no-ops.
		isConnected.Store(true)
		return nil
	}
	sdp.log.Info("DNS Proxy started", logfields.Address, args.Address, logfields.Port, args.Port)

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
// 2. If the connection is successful, it tries to start the grpc streams using the connection.
// Each stream has its own wrapper, which handles the stream creation and errors.
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
			isConnected.Store(false)
			// 1. Try creating the connection to the cilium agent
			if sdp.connection == nil {
				err := sdp.ConnectToCiliumAgent()
				if err != nil {
					sdp.log.Error("Failed to connect to cilium agent", logfields.Error, err)
					return
				}

				// Should we recreate the other stream? For example, if FQDN mapping stream error
				// has caused the connection to be closed, do we need to recreate the dnsRulesStream?
				// As part of the connection close, we cancel the context of both streams, so the "other"
				// stream will error, and will recreate itself.
			}

			// 2. Try starting the cilium agent connection
			err = sdp.StartCiliumAgentConnection()
			if err != nil {
				sdp.log.Error("Failed to start cilium agent connection")
				return
			}
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

func (sdp *StandaloneDNSProxy) GetDNSMsgType(msg *dns.Msg) string {
	if msg.Response {
		return "response"
	}
	return "request"
}

func (s *StandaloneDNSProxy) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	s.log.Debug("Received DNS message", logfields.Message, msg)

	if stat.Err != nil {
		metrics.DNSRequestNotResolved.WithLabelValues(stat.Err.Error(), s.GetDNSMsgType(msg)).Inc()
	}

	if s.fqdnMappingStreamWrapper == nil {
		return fmt.Errorf("FQDN mapping stream wrapper is nil, not sending the mapping to Cilium agent")
	}

	qname, responseIPs, TTL, CNAMEs, rcode, answerTypes, qtypes, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		s.log.Error("cannot extract DNS message details", logfields.Error, err)
		metrics.DNSRequestNotResolved.WithLabelValues(err.Error(), s.GetDNSMsgType(msg)).Inc()
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
		metrics.DNSRequestNotResolved.WithLabelValues(err.Error(), s.GetDNSMsgType(msg)).Inc()
		return err
	}

	metrics := formatMetricsData(stat, epIPPort, serverID, serverAddr, msg.Response, CNAMEs, qtypes, answerTypes, allowed, protocol)

	messageID := uniqueID(int32(msg.Id), qname)
	s.log.Debug("Message id for DNS message, qname, messageID", logfields.DNSRequestID, msg.Id, logfields.Name, qname, logfields.ID, messageID)

	message := pb.FQDNMapping{
		FQDN:         qname,
		IPS:          ips,
		TTL:          TTL,
		ClientIp:     []byte(clientIp),
		ResponseCode: uint32(rcode),
		Metrics:      &metrics,
		RequestId:    messageID,
	}

	err = s.fqdnMappingStreamWrapper.AddFqdnMappingToSendChannelAndGetResponse(&message)
	if err != nil {
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

func (sdp *StandaloneDNSProxy) UpdateDNSRules(newRules *pb.DNSPolicyRules) {
	var revertFuncs revert.RevertStack
	var retErr error
	defer func() {
		if retErr != nil {
			sdp.log.Error("Failed to update DNS rules, reverting changes", logfields.Error, retErr)
			if rErr := revertFuncs.Revert(); rErr != nil {
				sdp.log.Error("Failed to revert DNS rules changes", logfields.Error, rErr)
			}
		}
	}()

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
	revert, err := sdp.DNSProxy.UpdateAllowed(newRules.GetEndpointId(), destPortProto, l7DataMap)
	if err != nil {
		sdp.log.Error("Failed to update DNS rules for endpoint", logfields.EndpointID, newRules.GetEndpointId(), logfields.Error, err)
		metrics.RetrieveDNSRules.WithLabelValues(err.Error()).Inc()
		retErr = err
		return
	}
	revertFuncs.Push(revert)
}
