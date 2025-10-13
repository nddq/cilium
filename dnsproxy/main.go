package main

import (
	"github.com/cilium/cilium/dnsproxy/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	dnsProxyHive := hive.New(cmd.DNSProxy)

	cmd.Execute(cmd.NewDNSProxyCmd(dnsProxyHive))
}
