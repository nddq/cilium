package cmd

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/dnsproxy/api"
	"github.com/cilium/cilium/dnsproxy/metrics"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	DNSProxy = cell.Module(
		"standalone-dns-proxy",
		"Standalone DNS Proxy",

		cell.Provide(func() *option.DaemonConfig { return option.Config }),
		cell.Config(service.DefaultConfig),
		cell.Invoke(registerDNSProxyHooks),
		api.ServerCell,
		api.HealthHandlerCell(),
		api.ReadinessHandlerCell(isConnected.Load),
	)

	binaryName = "standalone-dns-proxy"

	// StandaloneDNSPRoxy is able to connect to the cilium agent
	isConnected atomic.Bool
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

	Logger     *slog.Logger
	Lifecycle  cell.Lifecycle
	FQDNConfig service.FQDNConfig
}

func registerDNSProxyHooks(params standaloneDNSProxyParams) {
	params.Logger.Info("Populating configuration from CLI")
	sdp := NewStandaloneDNSProxy(params.Logger)

	args := &StandaloneDNSProxyArgs{
		Address:                "",
		Port:                   uint16(option.Config.ToFQDNsProxyPort),
		IPv4:                   option.Config.EnableIPv4,
		IPv6:                   option.Config.EnableIPv6,
		EnableDNSCompression:   option.Config.ToFQDNsEnableDNSCompression,
		MaxRestoreDNSIps:       option.Config.DNSMaxIPsPerRestoredRule,
		ConcurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
		ConcurrencyGracePeriod: option.Config.DNSProxyConcurrencyProcessingGracePeriod,
		Logger:                 params.Logger,
		ToFqdnServerPort:       uint16(params.FQDNConfig.StandaloneDNSProxyServerPort),
		EnableL7Proxy:          option.Config.EnableL7Proxy,
	}

	// Todo: add the log with individual fields
	params.Logger.Info("Starting standalone DNS proxy",
		logfields.Address, args.Address,
		logfields.Port, args.Port,
		logfields.IPv4, args.IPv4,
		logfields.IPv6, args.IPv6,
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			metrics.Register()

			return sdp.StartStandaloneDNSProxy(args)
		},
		OnStop: func(cell.HookContext) error {
			metrics.Unregister()

			return sdp.StopStandaloneDNSProxy()
		},
	})
}
