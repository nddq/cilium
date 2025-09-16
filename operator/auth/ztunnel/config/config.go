// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import "github.com/spf13/pflag"

type ZtunnelConfig struct {
	Enabled bool `mapstructure:"ztunnel-mtls-enabled"`
}

var DefaultZtunnelConfig = ZtunnelConfig{
	Enabled: false,
}

func (cfg ZtunnelConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("ztunnel-mtls-enabled", cfg.Enabled, "Enable ztunnel mTLS support (alpha)")
}
