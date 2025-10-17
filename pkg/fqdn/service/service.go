// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	azureDNSProxy "github.com/cilium/cilium/api/v1/dnsproxy"
	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

// FQDNDataServer is the server for the standalone DNS proxy grpc server
// It is responsible for handling the FQDN mapping requests from the SDP
// and sending the DNS Policy updates to the SDP.
type FQDNDataServer struct {
	pb.UnimplementedFQDNDataServer

	// port is the port on which the standalone DNS proxy grpc server will run
	port int

	// grpcServer is the grpc server for the standalone DNS proxy
	grpcServer *grpc.Server

	endpointManager endpointmanager.EndpointManager

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg messagehandler.DNSMessageHandler

	// identityToIPMutex is a mutex to protect the current state of the identity to Ip mapping
	identityToIPMutex lock.Mutex

	// currentIdentityToIP is a map of the identity to list of IPs
	currentIdentityToIP map[identity.NumericIdentity][]netip.Prefix

	// prefixLengths tracks the unique set of prefix lengths for IPv4 and
	// IPv6 addresses in order to optimize longest prefix match lookups.
	prefixLengths *counter.PrefixLengthCounter

	// log is the logger for the FQDNDataServer
	log *slog.Logger

	// listener is used to create a net.Listener when starting the grpc server
	listener listenConfig

	// enabled indicates whether the standalone DNS proxy is enabled
	// This field is set to true only when ALL the following conditions are met:
	//
	// | Flag/Setting                           | Required Value | Description                                    |
	// |----------------------------------------|----------------|------------------------------------------------|
	// | EnableStandaloneDNSProxy               | true           | Feature flag to enable standalone DNS proxy   |
	// | DaemonConfig.EnableL7Proxy             | true           | L7 proxy must be enabled as a prerequisite    |
	// | DaemonConfig.ToFQDNsProxyPort          | > 0            | Valid port for FQDN proxy                     |
	// | Config.StandaloneDNSProxyServerPort    | > 0            | Valid port for standalone DNS proxy server    |
	//
	// If ANY of these conditions is not met, enabled will be false and the standalone
	// DNS proxy will not function. The IsEnabled() method returns this field's value.
	enabled bool

	// Azure's DNS Proxy fields
	azureDNSProxy.UnimplementedAzureFQDNDataServer

	ctx    context.Context
	cancel context.CancelFunc

	streams lock.Map[azureDNSProxy.AzureFQDNData_SubscribeToDNSRulesServer, context.CancelFunc]

	localRules map[uint64]map[restore.PortProto]policy.L7DataMap

	proxyAccessLogger accesslog.ProxyAccessLogger
}
type updateOnDNSMsgFunc func(responseIPs []netip.Addr, lookupTime time.Time, qname string, TTL uint32, ep *endpoint.Endpoint, stat *dnsproxy.ProxyRequestContext)

// ConvertToUint16 converts a slice of uint32 to a slice of uint16
func ConvertToUint16(input []uint32) []uint16 {
	output := make([]uint16, len(input))
	for i, v := range input {
		output[i] = uint16(v)
	}
	return output
}

var (
	kaep = keepalive.EnforcementPolicy{
		PermitWithoutStream: true, // Allow pings even when there are no active streams
	}
	kasp = keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}
)

// listenConfig is an interface that abstracts the creation of a net.Listener.
type listenConfig interface {
	Listen(ctx context.Context, network, addr string) (net.Listener, error)
}

// defaultListener implements Listener by using net.ListenConfig.
type defaultListener struct{}

func (d *defaultListener) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, network, addr)
}

var _ listenConfig = &defaultListener{}

func newDefaultListener() listenConfig {
	return &defaultListener{}
}

type PolicyUpdater interface {
	// UpdatePolicyRules is used to update the current state of the policy rules at the
	// gRPC server. These rules are sent to the standalone DNS proxy.
	// This is currently being called whenever there is a policy regeneration event
	// for an endpoint.
	UpdatePolicyRules(map[identity.NumericIdentity]policy.SelectorPolicy, bool) error

	// IsEnabled returns true if the standalone DNS proxy is enabled
	IsEnabled() bool

	// Azure's DNS Proxy methods
	// UpdateSDPAllowed updates the rules in the SDP DNS proxy with newRules.
	// This is called from the cilium-agent when the policy is updated.
	UpdateSDPAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) error
}

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we start a goroutine to receive the DNS policies ACKs
// The flow of the method is as follows:
// 1. Add the stream to the map( called by the client i.e SDP)
// 2. Start a goroutine to receive the DNS policies ACKs for that particular client.
// 3. Send the current state of the DNS rules to the client (We store the current state fo DNS rules during the endpoint regeneration see UpdatePolicyRulesLocked)
// 4. Wait for the context to be done
// Note: this method is left empty on purpose and will be update with the actual implementation in the future PRs for the standalone DNS proxy
func (s *FQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	// This is a temporary implementation to send the current state of the DNS rules to the client and used for testing
	stream.Send(&pb.PolicyState{RequestId: "test"})
	return nil
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(endpointManager endpointmanager.EndpointManager, updateOnDNSMsg messagehandler.DNSMessageHandler, port int, logger *slog.Logger, listener listenConfig, proxyLogger accesslog.ProxyAccessLogger) *FQDNDataServer {
	ctx, cancel := context.WithCancel(context.Background())
	fqdnDataServer := &FQDNDataServer{
		port:                port,
		endpointManager:     endpointManager,
		updateOnDNSMsg:      updateOnDNSMsg,
		currentIdentityToIP: make(map[identity.NumericIdentity][]netip.Prefix),
		log:                 logger,
		prefixLengths:       counter.DefaultPrefixLengthCounter(),
		listener:            listener,
		enabled:             true,

		// Azure's DNS Proxy fields
		ctx:               ctx,
		cancel:            cancel,
		streams:           lock.Map[azureDNSProxy.AzureFQDNData_SubscribeToDNSRulesServer, context.CancelFunc]{},
		localRules:        make(map[uint64]map[restore.PortProto]policy.L7DataMap),
		proxyAccessLogger: proxyLogger,
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	fqdnDataServer.grpcServer = grpcServer
	pb.RegisterFQDNDataServer(grpcServer, fqdnDataServer)

	azureDNSProxy.RegisterAzureFQDNDataServer(grpcServer, fqdnDataServer)
	return fqdnDataServer
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	s.identityToIPMutex.Lock()
	defer s.identityToIPMutex.Unlock()

	if cidr.ClusterID() != 0 {
		return
	}
	prefix := cidr.AsPrefix()
	if cidr.ClusterID() == 0 {
		switch modType {
		case ipcache.Upsert:
			if oldID != nil {
				// Remove from the old identity
				s.deleteFromIdentityToIPLocked(oldID, prefix)
			}
			s.currentIdentityToIP[newID.ID] = append(s.currentIdentityToIP[newID.ID], prefix)
			s.prefixLengths.Add([]netip.Prefix{prefix})
		case ipcache.Delete:
			if oldID != nil {
				s.deleteFromIdentityToIPLocked(oldID, prefix)
			}
		}
	}
}

// deleteFromIdentityToIPLocked deletes the given IP from the identity to IP mapping
// It is called when the IP identity cache changes and the IP is deleted from the mapping
// It is also called when the IP is upserted with a new identity
// It removes the prefix from the prefixLengths map
// It is called with the identityToIpMutex lock held
func (s *FQDNDataServer) deleteFromIdentityToIPLocked(identity *ipcache.Identity, prefix netip.Prefix) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	if ips, ok := s.currentIdentityToIP[identity.ID]; ok {
		newIPs := slices.DeleteFunc(ips, func(existing netip.Prefix) bool {
			if existing == prefix {
				s.prefixLengths.Delete([]netip.Prefix{prefix})
				return true
			}
			return false
		})
		if len(newIPs) == 0 {
			delete(s.currentIdentityToIP, identity.ID)
		} else {
			s.currentIdentityToIP[identity.ID] = newIPs
		}
	}
	return nil
}

// UpdatePolicyRules updates the current state of the DNS rules with the given policies and sends the current state of the DNS rules to the client
// This method is called:
// 1. when the DNS rules are updated during the endpoint regeneration, we store the state of the DNS rules with flag rulesUpdate as true
// 2. when the client subscribes to DNS policies, we send the current state of the DNS rules to the client(flag rulesUpdate as false)
// 3. when the IP identity cache changes, we update the current state of the identity to IP mapping and send the current state of the DNS rules to
// the client(flag rulesUpdate as false)
// Note: this method is left empty on purpose and will be updated with the actual implementation in the future PRs for the standalone DNS proxy
func (s *FQDNDataServer) UpdatePolicyRules(policies map[identity.NumericIdentity]policy.SelectorPolicy, rulesUpdate bool) error {
	return nil
}

func (s *FQDNDataServer) IsEnabled() bool {
	return s != nil && s.enabled
}

// UpdateMappingRequest updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
// Note: this method is left empty on purpose and will be updated with the actual implementation in the future PRs for the standalone DNS proxy
func (s *FQDNDataServer) UpdateMappingRequest(ctx context.Context, mappings *pb.FQDNMapping) (*pb.UpdateMappingResponse, error) {
	return &pb.UpdateMappingResponse{
		Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
	}, nil
}

// ListenAndServe starts the Standalone DNS Proxy gRPC server on the given port
func (s *FQDNDataServer) ListenAndServe(ctx context.Context, health cell.Health) error {
	listenErrs := make(chan error)
	go func() {
		defer close(listenErrs)

		address := fmt.Sprintf("localhost:%d", s.port)
		s.log.Info("Starting Standalone DNS Proxy server on", logfields.Address, address)
		lis, err := s.listener.Listen(ctx, "tcp", address)
		if err != nil {
			s.log.Error("Failed to listen", logfields.Error, err)
			listenErrs <- err
			return
		}

		if err := s.grpcServer.Serve(lis); err != nil {
			s.log.Error("Failed to serve the standalone DNS Proxy gRPC server", logfields.Error, err)
			listenErrs <- err

		}
	}()

	health.OK(fmt.Sprintf("Serving at %d", s.port))

	select {
	case err := <-listenErrs:
		return err
	case <-ctx.Done():
		s.Stop()
		<-listenErrs
		return nil
	}
}

func (s *FQDNDataServer) Stop() {
	if s.grpcServer == nil {
		return
	}

	s.cleanupStreams()
	// Stop the grpc server
	s.grpcServer.GracefulStop()
}

/* Azure's DNS Proxy methods */
/*
UpdateSDPAllowed updates the rules in the SDP DNS proxy with newRules.
This is called from the cilium-agent when the policy is updated.
*/
func (s *FQDNDataServer) UpdateSDPAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) error {
	s.log.Debug("Policy updates for SDP", logfields.EndpointID, endpointID, logfields.Port, destPortProto, logfields.Rule, newRules)
	dnsPolicyRule := make([]*azureDNSProxy.DNSPolicyRule, 0, len(newRules))
	for selector, policy := range newRules {
		if policy == nil || policy.DNS == nil {
			continue
		}
		fqdnSelectors := make([]*azureDNSProxy.FQDNSelector, 0, len(policy.DNS))
		for _, portRules := range policy.DNS {
			fqdnSelectors = append(fqdnSelectors, &azureDNSProxy.FQDNSelector{
				MatchName:    portRules.MatchName,
				MatchPattern: portRules.MatchPattern,
			})
		}
		var selections []uint32
		for _, selc := range selector.GetSelections(versioned.Latest()) {
			selections = append(selections, uint32(selc))
		}

		dnsPolicyRule = append(dnsPolicyRule, &azureDNSProxy.DNSPolicyRule{
			SelectorString: selector.String(),
			PortRules:      fqdnSelectors,
			Selections:     selections,
		})
	}
	dnsPolicyRules := &azureDNSProxy.DNSPolicyRules{
		EndpointId: endpointID,
		Port:       uint32(destPortProto.Port()),
		Protocol:   uint32(destPortProto.Protocol()),
		Rules:      dnsPolicyRule,
	}

	// Storing the rules for the endpoint
	// This is avoid the race between CA and SDP during new policy updates from CA along with SDP restart:
	// - CA is updating the DNS rules, alongside SDP is also coming up.
	// - Before cilium updates the dns rules in filesystem, SDP reads the (n-1)th updated rules.
	// - Cilium agent tries to send the nth rules ro SDP, but SDP has not yet created the connection with CA.
	// - Hence, the new rules are not updated in SDP. Now CA is aware of new rules and but not sdp.
	// - We send the latest rules to SDP on connection establishment. Making cilium agent as the source truth.
	if _, ok := s.localRules[endpointID]; !ok {
		s.localRules[endpointID] = make(map[restore.PortProto]policy.L7DataMap)
	}
	s.localRules[endpointID][destPortProto] = newRules

	s.log.Debug("Sending Policy updates to sdp", logfields.Rules, dnsPolicyRules)
	s.streams.Range(func(stream azureDNSProxy.AzureFQDNData_SubscribeToDNSRulesServer, cancel context.CancelFunc) bool {
		s.log.Debug("Sending update to stream", logfields.Key, stream)
		if err := stream.Send(dnsPolicyRules); err != nil {
			s.log.Error("Failed to send update", logfields.Error, err)
			// Cancel the goroutine and remove the stream from the map
			cancel()
		}
		return true
	})
	return nil
}

func (s *FQDNDataServer) DeleteStream(stream azureDNSProxy.AzureFQDNData_SubscribeToDNSRulesServer) {
	_, ok := s.streams.Load(stream)
	if ok {
		s.log.Info("Deleting stream", logfields.Key, stream)
		s.streams.Delete(stream)
	} else {
		s.log.Warn("Stream not found", logfields.Key, stream)
	}
}

// SubscribeToDNSRules is the gRPC handler for the SubscribeToDNSRules RPC.
// SDP will call this method to subscribe to DNS rules.
func (s *FQDNDataServer) SubscribeToDNSRules(in *azureDNSProxy.Request, stream azureDNSProxy.AzureFQDNData_SubscribeToDNSRulesServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	s.streams.Store(stream, cancel)

	go func() {
		<-stream.Context().Done()
		// If the client has closed the connection, the context will be done
		s.log.Info("Client has closed the connection, closing the stream")
		s.DeleteStream(stream)
	}()

	//Send the current state of the DNS rules
	go func() {
		s.log.Debug("Sending current state of DNS rules")
		for endpointID, portRules := range s.localRules {
			for destPortProto, newRules := range portRules {
				err := s.UpdateSDPAllowed(endpointID, destPortProto, newRules)
				if err != nil {
					s.log.Error("Failed to send current state of DNS rules", logfields.Error, err)
					return
				}
			}
		}
	}()

	s.log.Debug("SubscribeToDNSRules waiting for context to be done")
	select {
	case <-streamCtx.Done():
		s.log.Info("Closing the stream")
		s.DeleteStream(stream)
		return streamCtx.Err()
	case <-s.ctx.Done():
		s.log.Info("SubscribeToDNSRules done")
		return s.ctx.Err()
	}
}

// cleanupStreams handles the cleanup of streams when the server's context is cancelled.
func (s *FQDNDataServer) cleanupStreams() {
	s.streams.Range(func(stream azureDNSProxy.AzureFQDNData_SubscribeToDNSRulesServer, cancelFunc context.CancelFunc) bool {
		cancelFunc()
		if closer, ok := stream.(io.Closer); ok {
			err := closer.Close()
			if err != nil {
				s.log.Error("Error closing stream", logfields.Error, err)
			}
		} else {
			s.log.Warn("Stream does not implement io.Closer", logfields.Key, stream)
		}
		s.streams.Delete(stream)
		return true
	})
	s.log.Info("All streams have been cleaned up")
}

func (s *FQDNDataServer) UpdateMappings(stream azureDNSProxy.AzureFQDNData_UpdateMappingsServer) error {
	s.log.Debug("UpdateMappings stream started")
	for {
		select {
		case <-s.ctx.Done():
			s.log.Info("Context cancelled, stopping UpdateMapping stream")
			return nil
		default:
			update, err := stream.Recv()
			if err == io.EOF {
				// End of stream
				s.log.Info("Stream closed by client")
				return nil
			}
			if err != nil {
				s.log.Error("Failed to receive update", logfields.Error, err)
				return err
			}
			s.log.Debug("Received update", logfields.Response, update)
			requestId := update.GetRequestId()
			response := &azureDNSProxy.Result{
				Success:   true,
				RequestId: requestId,
			}
			if err := s.updateFQDNMapping(update); err != nil {
				s.log.Error("Failed to update mapping", logfields.Error, err)
				response.Success = false
				if sendErr := s.sendResponse(stream, response); sendErr != nil {
					s.log.Error("Failed to send response", logfields.Error, sendErr)
				}
				return err
			}

			if err := s.sendResponse(stream, response); err != nil {
				s.log.Error("Failed to send response", logfields.Error, err)
				return err
			}
		}
	}
}

func (s *FQDNDataServer) sendResponse(stream azureDNSProxy.AzureFQDNData_UpdateMappingsServer, response *azureDNSProxy.Result) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendErr := make(chan error, 1)

	go func() {
		sendErr <- stream.Send(response)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-sendErr:
		return err
	}
}

// updateFQDNMapping updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are empty, log the request(for hubble to read)
// 4. If the IPs are not empty, update the cilium agent with the mapping and  log the request(for hubble to read)
func (s *FQDNDataServer) updateFQDNMapping(mappings *azureDNSProxy.AzureFQDNMapping) error {
	// The time is ideally from the time we receive the DNS response
	// but for now we will use the current time when we receive in the server
	now := time.Now()
	var ips []netip.Addr
	for _, ip := range mappings.GetIPS() {
		ipaddress, err := netip.ParseAddr(string(ip))
		if err != nil {
			s.log.Error("Failed to parse IP", logfields.IPAddr, ip)
			return fmt.Errorf("failed to parse IP: %s", ip)
		}
		ips = append(ips, ipaddress)
	}
	metrics := mappings.GetMetrics()

	endpointAddr, err := netip.ParseAddr(string(mappings.ClientIp))
	if err != nil {
		return fmt.Errorf("invalid IP %s for endpoint lookup", string(mappings.ClientIp))
	}

	ep := s.endpointManager.LookupIP(endpointAddr)
	if ep == nil {
		s.log.Error("endpoint not found for IP", logfields.IPAddr, mappings.ClientIp)
		return fmt.Errorf("endpoint not found for IP: %s", mappings.ClientIp)
	}

	if len(mappings.GetIPS()) == 0 {
		// We don't have any IPs to update the mapping with
		s.logDNSRequest(ep, metrics, ips, mappings.GetFQDN(), mappings.GetTTL(), mappings.GetResponseCode())
		return nil
	}

	if mappings.GetResponseCode() == dns.RcodeSuccess {
		s.updateOnDNSMsg.UpdateOnDNSMsg(now, ep, mappings.GetFQDN(), ips, int(mappings.GetTTL()), nil)
	}

	s.logDNSRequest(ep, metrics, ips, mappings.GetFQDN(), mappings.GetTTL(), mappings.GetResponseCode())
	return nil
}

// logDNSRequest logs the DNS request to be used by hubble for metrics
// Cilium agent calls this function to log the DNS request when the SDP sends the fqdn mapping
// It follows the same format as the cilium inbuilt dns proxy
// The data from the SDP is parsed and logged for hubble to read
func (s *FQDNDataServer) logDNSRequest(ep *endpoint.Endpoint, metrics *azureDNSProxy.MetricsData, ips []netip.Addr, fqdn string, TTL uint32, responseCode uint32) {
	if metrics == nil {
		s.log.Debug("Metrics data is nil")
		return
	}
	var verdict accesslog.FlowVerdict
	var reason string
	allowed := metrics.GetAllowed()
	statErr := metrics.GetProcessingStats().GetErr()
	switch {
	case statErr != "":
		verdict = accesslog.VerdictError
		reason = "Error: " + statErr
	case allowed:
		verdict = accesslog.VerdictForwarded
		reason = "Allowed by policy"
	case !allowed:
		verdict = accesslog.VerdictDenied
		reason = "Denied by policy"
	}

	flowType, addrInfo := GetFlowType(ep, metrics.GetEndpointIpPort(), metrics.GetServerAddr(),
		identity.NumericIdentity(metrics.GetServerIdentity()), metrics.GetDnsResponseData().GetResponse())
	var protoID = u8proto.ProtoIDs[strings.ToLower(metrics.GetProtocol())]

	logContext, lcncl := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer lcncl()

	record := s.proxyAccessLogger.NewLogRecord(flowType, false,
		func(lr *accesslog.LogRecord, _ accesslog.EndpointInfoRegistry) {
			lr.TransportProtocol = accesslog.TransportProtocol(protoID)
		},
		accesslog.LogTags.Verdict(verdict, reason),
		accesslog.LogTags.Addressing(logContext, addrInfo),
		accesslog.LogTags.DNS(&accesslog.LogRecordDNS{
			Query:             fqdn,
			IPs:               ips,
			TTL:               TTL,
			CNAMEs:            metrics.GetDnsResponseData().GetCnames(),
			ObservationSource: accesslog.DNSDataSource(metrics.GetProcessingStats().GetDataSource()),
			RCode:             int(responseCode),
			QTypes:            ConvertToUint16(metrics.GetDnsResponseData().GetQtypes()),
			AnswerTypes:       ConvertToUint16(metrics.GetDnsResponseData().GetAnswerTimes()),
		}),
	)
	s.proxyAccessLogger.Log(record)
}

// Get the flow type of the DNS message
func GetFlowType(ep *endpoint.Endpoint, epIpPort string, serverAddr string, serverID identity.NumericIdentity, response bool) (accesslog.FlowType, accesslog.AddressingInfo) {
	// We determine the direction based on the DNS packet. The observation
	// point is always Egress, however.
	var flowType accesslog.FlowType
	var addrInfo accesslog.AddressingInfo

	if response {
		flowType = accesslog.TypeResponse
		addrInfo.DstIPPort = epIpPort
		addrInfo.DstEPID = ep.GetID()
		// ignore error; log fields are best effort. Only returns error if endpoint
		// is going away.
		addrInfo.DstSecIdentity, _ = ep.GetSecurityIdentity()
		addrInfo.SrcIPPort = serverAddr
		addrInfo.SrcIdentity = serverID
	} else {
		flowType = accesslog.TypeRequest
		addrInfo.SrcIPPort = epIpPort
		addrInfo.SrcEPID = ep.GetID()
		// ignore error; same reason as above.
		addrInfo.SrcSecIdentity, _ = ep.GetSecurityIdentity()
		addrInfo.DstIPPort = serverAddr
		addrInfo.DstIdentity = serverID
	}
	return flowType, addrInfo
}
