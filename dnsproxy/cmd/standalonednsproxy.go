package cmd

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/dns"
)

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
}

type StandaloneDNSProxy struct {
	DNSProxy *dnsproxy.DNSProxy
}

func NewStandaloneDNSProxy() *StandaloneDNSProxy {
	return &StandaloneDNSProxy{}
}

func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	sdp.DNSProxy.Cleanup()
	return nil
}

func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy(args *StandaloneDNSProxyArgs) error {
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
	return nil
}

func (sdp *StandaloneDNSProxy) LookupEPByIP(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	return nil, false, nil
}

func (sdp *StandaloneDNSProxy) LookupByIdentity(nid identity.NumericIdentity) []string {
	return nil
}

func (sdp *StandaloneDNSProxy) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	return ipcache.Identity{}, false
}

func (s *StandaloneDNSProxy) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	return nil
}
