package api

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	// StandaloneDNSProxyAPIServeAddr is the "<ip>:<port>" on which to serve api requests
	// from the standalone dns proxy.
	StandaloneDNSProxyAPIServeAddr = "standalone-dns-proxy-api-serve-addr"

	// StandaloneDNSProxyAPIServeAddrDefault is the default "<ip>:<port>" value on which to serve
	// api requests from the standalone dns proxy.
	StandaloneDNSProxyAPIServeAddrDefault = "localhost:9235"
)

var (
	log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "standalone-dns-proxy-api")
)

var ServerCell = cell.Module(
	"standalone-dns-proxy-api",
	"Standalone DNS Proxy API Server",

	cell.Config(Config{}),
	cell.Provide(newServer),
	cell.Invoke(func(Server) {}),
)

type Config struct {
	StandaloneDNSProxyAPIServeAddr string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(StandaloneDNSProxyAPIServeAddr, StandaloneDNSProxyAPIServeAddrDefault, "Address to serve API requests")
}
