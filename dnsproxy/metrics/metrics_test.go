package metrics_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/dnsproxy/cmd"
	"github.com/cilium/cilium/dnsproxy/metrics"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	cilMetrics "github.com/cilium/cilium/pkg/metrics"
)

type mockResponseWriter struct{}

func (m *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}
func (m *mockResponseWriter) WriteMsg(*dns.Msg) error {
	return nil
}
func (m *mockResponseWriter) LocalAddr() net.Addr {
	return &net.IPAddr{}
}
func (m *mockResponseWriter) RemoteAddr() net.Addr {
	return &net.IPAddr{}
}
func (m *mockResponseWriter) TsigTimersOnly(bool)      {}
func (m *mockResponseWriter) Hijack()                  {}
func (m *mockResponseWriter) WriteHeaderNow()          {}
func (m *mockResponseWriter) SetHeader(string, string) {}
func (m *mockResponseWriter) TsigStatus() error {
	return nil
}
func (m *mockResponseWriter) Close() error {
	return nil
}

func TestNotifyOnDNSMsgMetrics(t *testing.T) {
	// Create a StandaloneDNSProxy instance
	sdp := &cmd.StandaloneDNSProxy{}
	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Address:                "",
		IPv4:                   true,
		IPv6:                   true,
		EnableDNSCompression:   true,
		MaxRestoreDNSIPs:       1000,
		ConcurrencyLimit:       0,
		ConcurrencyGracePeriod: 0,
		Logger:                 hivetest.Logger(t),
	}

	proxy := dnsproxy.NewDNSProxy(dnsProxyConfig, // any address, any port, enable ipv4, enable ipv6, enable compression, max 1000 restore IPs
		sdp, //
		// LookupEPByIP
		func(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
			return &endpoint.Endpoint{}, false, nil
		},
		// NotifyOnDNSMsg
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)
	metrics.Register()
	initialValue := cilMetrics.ProxyDNSRequestsTotal.Get()
	query := "bing.com."

	sdp.DNSProxy = proxy
	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	w := &mockResponseWriter{}
	sdp.DNSProxy.ServeDNS(w, request)
	finalValue := cilMetrics.ProxyDNSRequestsTotal.Get()
	assert.Equal(t, initialValue+1, finalValue, "DNSRequestsTotal metric should increase by 1")
}
