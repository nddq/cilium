// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"time"

	"github.com/spf13/pflag"
)

type ClientConfig struct {
	SpireAgentSocketPath         string        `mapstructure:"ztunnel-spire-agent-socket"`
	SpireServerAddress           string        `mapstructure:"ztunnel-spire-server-address"`
	SpireServerConnectionTimeout time.Duration `mapstructure:"ztunnel-spire-server-connection-timeout"`
	SpiffeTrustDomain            string        `mapstructure:"ztunnel-spiffe-trust-domain"`
}

var DefaultClientConfig = ClientConfig{
	SpireAgentSocketPath:         "/run/spire/sockets/agent/agent.sock",
	SpireServerAddress:           "spire-server.kube-system.svc:8081",
	SpireServerConnectionTimeout: 30 * time.Second,
	SpiffeTrustDomain:            "cluster.local",
}

// Flags adds the flags used by ClientConfig.
func (cfg ClientConfig) Flags(flags *pflag.FlagSet) {
	flags.String("ztunnel-spire-agent-socket",
		cfg.SpireAgentSocketPath,
		"The path for the SPIRE admin agent Unix socket.")
	flags.String("ztunnel-spire-server-address",
		cfg.SpireServerAddress,
		"SPIRE server endpoint.")
	flags.Duration("ztunnel-spire-server-connection-timeout",
		cfg.SpireServerConnectionTimeout,
		"SPIRE server connection timeout.")
	flags.String("ztunnel-spiffe-trust-domain",
		cfg.SpiffeTrustDomain,
		"The trust domain for the SPIFFE identity.")
}
