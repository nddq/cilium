package cmd

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/dnsproxy/metrics"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	ciliumdns "github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
)

func TestStandaloneDNSProxy_NotifyOnDNSMsg_NilFqdnMappingStreamWrapper(t *testing.T) {
	// Create a StandaloneDNSProxy instance with nil fqdnMappingStreamWrapper
	sdp := &StandaloneDNSProxy{
		fqdnMappingStreamWrapper: nil,
		log:                      hivetest.Logger(t),
	}

	// Prepare test data
	lookupTime := time.Now()
	ep := &endpoint.Endpoint{}
	epIPPort := "127.0.0.1:12345"
	serverID := identity.NumericIdentity(1234)
	serverAddr := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 53)
	msg := &ciliumdns.Msg{}
	protocol := "udp"
	allowed := true
	stat := &dnsproxy.ProxyRequestContext{}

	// Call NotifyOnDNSMsg and ensure it doesn't crash
	err := sdp.NotifyOnDNSMsg(lookupTime, ep, epIPPort, serverID, serverAddr, msg, protocol, allowed, stat)

	// Assert that an error is returned indicating the nil fqdnMappingStreamWrapper
	if err == nil {
		t.Fatal("expected an error, but got nil")
	}

	if err.Error() != "FQDN mapping stream wrapper is nil, not sending the mapping to Cilium agent" {
		t.Fatalf("mismatched error %s", err.Error())
	}
}

func TestNotifyOnDNSMsgMetricsOnFailure(t *testing.T) {
	metrics.Register()

	// Create a StandaloneDNSProxy instance with nil fqdnMappingStreamWrapper
	sdp := &StandaloneDNSProxy{
		log: hivetest.Logger(t),
	}

	// Prepare test data
	lookupTime := time.Now()
	ep := &endpoint.Endpoint{}
	epIPPort := "127.0.0.1:12345"
	serverID := identity.NumericIdentity(1234)
	serverAddr := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 53)
	msg := &ciliumdns.Msg{}
	protocol := "udp"
	allowed := true
	testErr := errors.New("test error")
	stat := &dnsproxy.ProxyRequestContext{
		Err: testErr,
	}

	// case 1: Failure from the dns proxy updates the metrics
	m := &dto.Metric{}
	metrics.DNSRequestNotResolved.WithLabelValues(testErr.Error(), "request").Write(m)
	assert.Equal(t, float64(0), m.GetCounter().GetValue(), "DNSRequestNotResolved metric should not be incremented")
	sdp.NotifyOnDNSMsg(lookupTime, ep, epIPPort, serverID, serverAddr, msg, protocol, allowed, stat)
	metrics.DNSRequestNotResolved.WithLabelValues(testErr.Error(), "request").Write(m)
	assert.Equal(t, float64(1), m.GetCounter().GetValue(), "DNSRequestNotResolved metric should be incremented")

	sdp.fqdnMappingStreamWrapper = &FqdnMappingStreamWrapper{}

	// case 2: Failure from the DNS msg processing
	msg = &ciliumdns.Msg{}
	dnsErr := "Invalid DNS message"
	metrics.DNSRequestNotResolved.WithLabelValues(dnsErr, "request").Write(m)
	assert.Equal(t, float64(0), m.GetCounter().GetValue(), "DNSRequestNotResolved metric should not be incremented")
	err := sdp.NotifyOnDNSMsg(lookupTime, ep, epIPPort, serverID, serverAddr, msg, protocol, allowed, stat)
	metrics.DNSRequestNotResolved.WithLabelValues(dnsErr, "request").Write(m)
	assert.Equal(t, float64(1), m.GetCounter().GetValue(), "DNSRequestNotResolved metric should be incremented")
	assert.Error(t, err, "Expected an error from NotifyOnDNSMsg due to nil FQDN mapping stream wrapper")

	// case 3: Invalid IP:port format
	msg = &ciliumdns.Msg{
		Question: []ciliumdns.Question{
			{
				Name:  "example.com.",
				Qtype: ciliumdns.TypeA,
			},
		},
		MsgHdr: ciliumdns.MsgHdr{
			Response: true,
		},
	}
	epIPPort = "invalid-ip-port"
	epIPPortErr := "address invalid-ip-port: missing port in address"
	metrics.DNSRequestNotResolved.WithLabelValues(epIPPortErr, "response").Write(m)
	assert.Equal(t, float64(0), m.GetCounter().GetValue(), "DNSRequestNotResolved metric should not be incremented")
	err = sdp.NotifyOnDNSMsg(lookupTime, ep, epIPPort, serverID, serverAddr, msg, protocol, allowed, stat)
	metrics.DNSRequestNotResolved.WithLabelValues(epIPPortErr, "response").Write(m)
	assert.Equal(t, float64(1), m.GetCounter().GetValue(), "DNSRequestNotResolved metric should be incremented")
	assert.Error(t, err, "Expected an error from NotifyOnDNSMsg due to invalid IP:port format")
}

func TestUpdateDNSRules(t *testing.T) {
	// Create a StandaloneDNSProxy instance
	sdp := &StandaloneDNSProxy{
		log: hivetest.Logger(t),
	}
	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Address:                "",
		IPv4:                   true,
		IPv6:                   true,
		EnableDNSCompression:   true,
		MaxRestoreDNSIPs:       1000,
		ConcurrencyLimit:       0,
		ConcurrencyGracePeriod: 0,
	}

	// register metrics
	metrics.Register()

	proxy := dnsproxy.NewDNSProxy(dnsProxyConfig, // any address, any port, enable ipv4, enable ipv6, enable compression, max 1000 restore IPs
		sdp,
		// LookupEPByIP
		func(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
			return &endpoint.Endpoint{}, false, nil
		},
		// NotifyOnDNSMsg
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *ciliumdns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)
	sdp.DNSProxy = proxy

	// Case 1: Update DNS rules with valid data
	endpointID := 12345
	m := &dto.Metric{}
	errorLabel := "error parsing regexp: unexpected ): `^(?:@#))[.])$`"
	sdp.UpdateDNSRules(&pb.DNSPolicyRules{
		EndpointId: uint64(endpointID),
		Rules: []*pb.DNSPolicyRule{
			{
				PortRules: []*pb.FQDNSelector{
					{
						MatchPattern: "*",
					},
				},
			},
		}})
	metrics.RetrieveDNSRules.WithLabelValues(errorLabel).Write(m)
	assert.Equal(t, float64(0), m.GetCounter().GetValue(), "RetrieveDNSRules metric should not be incremented")

	// Case 2: Update DNS rules with invalid data
	sdp.UpdateDNSRules(&pb.DNSPolicyRules{
		EndpointId: uint64(endpointID),
		Rules: []*pb.DNSPolicyRule{
			{
				PortRules: []*pb.FQDNSelector{
					{
						MatchPattern: "@#))",
					},
				},
			},
		}})
	// Check if the error occurred as error is expected to happen
	metrics.RetrieveDNSRules.WithLabelValues(errorLabel).Write(m)
	assert.Equal(t, float64(1), m.GetCounter().GetValue(), "RetrieveDNSRules metric should be incremented")
}
