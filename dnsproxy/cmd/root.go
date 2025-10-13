package cmd

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	DNSProxy = cell.Module(
		"standalone-dns-proxy",
		"Standalone DNS Proxy",

		cell.Provide(func() *option.DaemonConfig { return option.Config }),
		cell.Invoke(registerDNSProxyHooks),
	)

	binaryName = "standalone-dns-proxy"
)

func NewDNSProxyCmd(h *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			initEnv(logging.DefaultSlogLogger, h.Viper())

			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				log.Fatal(err)
			}
		},
	}
	h.RegisterFlags(cmd.Flags())

	InitGlobalFlags(cmd, h.Viper())
	cmd.AddCommand(
		h.Command(),
	)
	cobra.OnInitialize(option.InitConfig(logging.DefaultSlogLogger, cmd, "Standalone-DNS-Proxy", "standalone-dns-proxy", h.Viper()))

	return cmd
}

func initEnv(logger *slog.Logger, vp *viper.Viper) {
	option.Config.Populate(logger, vp)
	option.LogRegisteredSlogOptions(vp, logger)
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type standaloneDNSProxyParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
}

func registerDNSProxyHooks(params standaloneDNSProxyParams) {
	params.Logger.Info("Populating configuration from CLI")
	sdp := NewStandaloneDNSProxy()

	args := &StandaloneDNSProxyArgs{
		address:                "",
		port:                   uint16(option.Config.ToFQDNsProxyPort),
		ipv4:                   option.Config.EnableIPv4,
		ipv6:                   option.Config.EnableIPv6,
		enableDNSCompression:   option.Config.ToFQDNsEnableDNSCompression,
		maxRestoreDNSIps:       option.Config.DNSMaxIPsPerRestoredRule,
		concurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
		concurrencyGracePeriod: option.Config.DNSProxyConcurrencyProcessingGracePeriod,
		logger:                 params.Logger,
	}

	// Todo: add the log with individual fields
	params.Logger.Info("Starting standalone DNS proxy",
		logfields.Address, args.address,
		logfields.Port, args.port,
		logfields.IPv4, args.ipv4,
		logfields.IPv6, args.ipv6,
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return sdp.StartStandaloneDNSProxy(args)
		},
		OnStop: func(cell.HookContext) error {
			return sdp.StopStandaloneDNSProxy()
		},
	})
}
