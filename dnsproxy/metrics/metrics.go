package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var (
	log = logging.DefaultSlogLogger
	// TODO: Add the port to the fqdn config map
	addr = ":9961"
)

// Namespace is the namespace key to use for standalone dns proxy metrics.
const Namespace = "standalone_dns_proxy"

type RegisterGatherer interface {
	prometheus.Registerer
	prometheus.Gatherer
}

var (
	// Registry is the global prometheus registry for standalone dns proxy metrics.
	Registry   RegisterGatherer
	shutdownCh chan struct{}
)

// Register registers metrics for standalone dns proxy.
func Register() {
	log.Info("Registering Standalone dns proxy metrics")

	Registry = prometheus.NewPedanticRegistry()

	registerMetrics()

	m := http.NewServeMux()
	m.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))

	listener, err := listenConfig()
	if err != nil {
		log.Error("Failed to create Standalone dns proxy metrics server listener", logfields.Error, err)
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: m,
	}

	shutdownCh = make(chan struct{})
	go func() {
		go func() {
			err := srv.Serve(listener)
			if errors.Is(err, http.ErrServerClosed) {
				log.Info("Metrics server shutdown successfully")
				return
			}
			log.Error("Metrics server Serve failed", logfields.Error, err)
		}()

		<-shutdownCh
		log.Info("Received shutdown signal")
		if err := srv.Shutdown(context.TODO()); err != nil {
			log.Error("Shutdown Standalone dns proxy metrics server failed", logfields.Error, err)
		}
	}()
}

// Creates a net.ListenConfig with Control function to set SO_REUSEPORT
func listenConfig() (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

// Unregister shuts down the metrics server.
func Unregister() {
	log.Info("Shutting down metrics server")

	if shutdownCh == nil {
		return
	}

	shutdownCh <- struct{}{}
}

var (
	// CiliumAgentConnection used to track the total number of errors occurred during connecting to cilium-agent.
	CiliumAgentConnection *prometheus.CounterVec

	// DNSRequestNotResolved used to track the total number of errors occurred during resolving DNS requests.
	DNSRequestNotResolved *prometheus.CounterVec

	// FQDNMappingSync used to track the total number of errors occurred during syncing FQDN mappings.
	FQDNMappingSync *prometheus.CounterVec

	// RetrieveDNSRules used to track the total number of errors occurred during retrieving the DNS rules.
	RetrieveDNSRules *prometheus.CounterVec
)

func registerMetrics() []prometheus.Collector {
	// Builtin process metrics
	Registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{Namespace: Namespace}))

	// Custom metrics
	var collectors []prometheus.Collector

	CiliumAgentConnection = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "cilium_agent_connection_errors",
		Help:      "Number of Cilium agent connection errors",
	}, []string{metrics.LabelError})
	collectors = append(collectors, CiliumAgentConnection)

	FQDNMappingSync = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "fqdn_mapping_sync_errors",
		Help:      "Number of fqdn mapping sync errors",
	}, []string{metrics.LabelError})
	collectors = append(collectors, FQDNMappingSync)

	RetrieveDNSRules = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "retrieve_dns_rules_errors",
		Help:      "Errors occurred during retrieving DNS rules",
	}, []string{metrics.LabelError})
	collectors = append(collectors, RetrieveDNSRules)

	DNSRequestNotResolved = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "dns_request_not_resolved_errors",
		Help:      "Number of dns request not resolved errors",
	}, []string{metrics.LabelError})
	collectors = append(collectors, DNSRequestNotResolved)

	Registry.MustRegister(collectors...)

	return collectors
}
