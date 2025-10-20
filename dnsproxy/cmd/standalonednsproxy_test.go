package cmd

import (
	"net/netip"
	"testing"
	"time"

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
