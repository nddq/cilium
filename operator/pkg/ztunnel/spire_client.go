package ztunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/operator/auth/spire"
	"github.com/cilium/cilium/pkg/backoff"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	notFoundError   = "NotFound"
	defaultParentID = "/ztunnel"
)

type SpireClient struct {
	clientCfg   spire.ClientConfig
	ztunnelCfg  Config
	logger      *slog.Logger
	entryClient entryv1.EntryClient
	entryMutex  lock.RWMutex
	k8sClient   k8sClient.Clientset
	initialized bool
}

var _ CAClient = &SpireClient{}

func newZtunnelSpireClient(k8sClient k8sClient.Clientset, clientCfg spire.ClientConfig, ztunnelCfg Config, logger *slog.Logger) CAClient {
	client := &SpireClient{
		clientCfg:  clientCfg,
		ztunnelCfg: ztunnelCfg,
		logger:     logger.With(logfields.LogSubsys, "ztunnel-spire-client"),
		k8sClient:  k8sClient,
	}

	return client
}

func (c *SpireClient) Initialize(ctx context.Context) error {
	if !c.ztunnelCfg.EnableZTunnel {
		return nil
	}
	if c.initialized {
		return nil
	}
	c.logger.InfoContext(ctx, "Initializing SPIRE client")
	attempts := 0
	backoffTime := backoff.Exponential{Logger: c.logger, Min: 200 * time.Millisecond, Max: 30 * time.Second}
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled while initializing SPIRE client: %w", ctx.Err())
	case <-time.After(5 * time.Second):
		// wait for 5 seconds before starting to connect to the SPIRE server
		// this is to give some time for the SPIRE server to start up
		// and for the cilium-operator to be registered in SPIRE.
		for {
			attempts++
			conn, err := c.connect(ctx)
			if err == nil {
				c.entryMutex.Lock()
				c.entryClient = entryv1.NewEntryClient(conn)
				c.entryMutex.Unlock()
				break
			}
			c.logger.WarnContext(ctx,
				"Unable to connect to SPIRE server",
				logfields.Attempt, attempts+1,
				logfields.Error, err)
			time.Sleep(backoffTime.Duration(attempts))
		}
		c.logger.InfoContext(ctx, "SPIRE client initialized")
		c.initialized = true
		return nil
	}
}

func (c *SpireClient) Upsert(ctx context.Context, ids ...*ID) error {
	if !c.ztunnelCfg.EnableZTunnel {
		return nil
	}
	if !c.initialized {
		return fmt.Errorf("SPIRE client not initialized")
	}

	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	if c.entryClient == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.clientCfg.SpireServerAddress)
	}

	newEntries := []*types.Entry{}
	updateEntries := []*types.Entry{}

	for _, id := range ids {
		entries, err := c.listEntries(ctx, id)
		if err != nil && !strings.Contains(err.Error(), notFoundError) {
			c.logger.ErrorContext(ctx, "Unable to list SPIRE entries",
				logfields.ID, id.String(),
				logfields.Error, err)
			return err
		}

		if entries == nil || len(entries.Entries) == 0 {
			c.logger.DebugContext(ctx, "Creating new SPIRE entry", logfields.ID, id.String())
			newEntries = append(newEntries, &types.Entry{
				ParentId: &types.SPIFFEID{
					TrustDomain: c.clientCfg.SpiffeTrustDomain,
					Path:        defaultParentID,
				},
				SpiffeId: &types.SPIFFEID{
					TrustDomain: c.clientCfg.SpiffeTrustDomain,
					Path:        id.String(),
				},
				Selectors: []*types.Selector{
					{
						Type:  "k8s",
						Value: "ns:" + id.Namespace,
					},
					{
						Type:  "k8s",
						Value: "sa:" + id.ServiceAccount,
					},
				},
			})
		} else {
			c.logger.DebugContext(ctx, "Updating existing SPIRE entry", logfields.ID, id.String())
			entry := entries.Entries[0]
			entry.Selectors = []*types.Selector{
				{
					Type:  "k8s",
					Value: "ns:" + id.Namespace,
				},
				{
					Type:  "k8s",
					Value: "sa:" + id.ServiceAccount,
				},
			}
			updateEntries = append(updateEntries, entry)
		}
	}

	if len(newEntries) == 0 && len(updateEntries) == 0 {
		c.logger.DebugContext(ctx, "No SPIRE entries to upsert")
		return nil
	}

	if len(newEntries) > 0 {
		_, err := c.entryClient.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{Entries: newEntries})
		if err != nil {
			c.logger.ErrorContext(ctx, "Unable to create SPIRE entries",
				logfields.Entries, newEntries,
				logfields.Error, err)
			return err
		}
	}

	if len(updateEntries) > 0 {
		_, err := c.entryClient.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{Entries: updateEntries})
		if err != nil {
			c.logger.ErrorContext(ctx, "Unable to update SPIRE entries",
				logfields.Entries, updateEntries,
				logfields.Error, err)
			return err
		}
	}

	return nil
}

func (c *SpireClient) Delete(ctx context.Context, entries ...*ID) error {
	if !c.ztunnelCfg.EnableZTunnel {
		return fmt.Errorf("ztunnel mTLS not enabled")
	}
	if !c.initialized {
		return fmt.Errorf("SPIRE client not initialized")
	}

	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	if c.entryClient == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.clientCfg.SpireServerAddress)
	}

	var entryIDs []string
	for _, id := range entries {
		list, err := c.listEntries(ctx, id)
		if err != nil {
			c.logger.ErrorContext(ctx, "Unable to list SPIRE entries",
				logfields.ID, id.String(),
				logfields.Error, err)
			return err
		}

		if list == nil || len(list.Entries) == 0 {
			c.logger.InfoContext(ctx, "No SPIRE entry found to delete", logfields.ID, id.String())
			continue
		}

		entryIDs = append(entryIDs, list.Entries[0].Id)
	}

	if len(entryIDs) == 0 {
		c.logger.DebugContext(ctx, "No SPIRE entries to delete")
		return nil
	}

	_, err := c.entryClient.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: entryIDs})
	if err != nil {
		c.logger.ErrorContext(ctx, "Unable to delete SPIRE entries",
			"ids", entryIDs,
			logfields.Error, err)
		return err
	}

	return nil
}

// listEntries returns the list of entries for the given ID.
// The maximum number of entries returned is 1, so page token can be ignored.
func (c *SpireClient) listEntries(ctx context.Context, id *ID) (*entryv1.ListEntriesResponse, error) {
	return c.entryClient.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			BySpiffeId: &types.SPIFFEID{
				TrustDomain: c.clientCfg.SpiffeTrustDomain,
				Path:        id.String(),
			},
			ByParentId: &types.SPIFFEID{
				TrustDomain: c.clientCfg.SpiffeTrustDomain,
				Path:        defaultParentID,
			},
			BySelectors: &types.SelectorMatch{
				Selectors: []*types.Selector{
					{
						Type:  "k8s",
						Value: "ns:" + id.Namespace,
					},
					{
						Type:  "k8s",
						Value: "sa:" + id.ServiceAccount,
					},
				},
				Match: types.SelectorMatch_MATCH_EXACT,
			},
		},
	})
}

func (c *SpireClient) connect(ctx context.Context) (*grpc.ClientConn, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, c.clientCfg.SpireServerConnectionTimeout)
	defer cancelFunc()

	resolvedTarget, err := resolvedK8sService(ctx, c.k8sClient, c.clientCfg.SpireServerAddress)
	if err != nil {
		c.logger.WarnContext(ctx,
			"Unable to resolve SPIRE server address, using original value",
			logfields.Error, err,
			logfields.URL, c.clientCfg.SpireServerAddress)
		resolvedTarget = &c.clientCfg.SpireServerAddress
	}

	// This is blocking till the cilium-operator is registered in SPIRE.
	source, err := workloadapi.NewX509Source(timeoutCtx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(fmt.Sprintf("unix://%s", c.clientCfg.SpireAgentSocketPath)),
			workloadapi.WithLogger(newSpiffeLogWrapper(c.logger)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509 source: %w", err)
	}

	trustedDomain, err := spiffeid.TrustDomainFromString(c.clientCfg.SpiffeTrustDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain: %w", err)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(trustedDomain))

	c.logger.InfoContext(ctx,
		"Trying to connect to SPIRE server",
		logfields.Address,
		c.clientCfg.SpireServerAddress,
		logfields.IPAddr,
		resolvedTarget,
	)
	conn, err := grpc.NewClient(*resolvedTarget, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection to SPIRE server: %w", err)
	}

	c.logger.InfoContext(ctx,
		"Connected to SPIRE server",
		logfields.Address, c.clientCfg.SpireServerAddress,
		logfields.IPAddr, resolvedTarget)
	return conn, nil
}

// resolvedK8sService resolves the given address to the IP address.
// The input must be in the form of <service-name>.<namespace>.svc.*:<port-number>,
// otherwise the original address is returned.
func resolvedK8sService(ctx context.Context, client k8sClient.Clientset, address string) (*string, error) {
	names := strings.Split(address, ".")
	if len(names) < 3 || !strings.HasPrefix(names[2], "svc") {
		return &address, nil
	}

	// retrieve the service and return its ClusterIP
	svc, err := client.CoreV1().Services(names[1]).Get(ctx, names[0], metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	res := net.JoinHostPort(svc.Spec.ClusterIP, port)
	return &res, nil
}

// spiffeLogWrapper is a log wrapper for the SPIRE client logs
// the log levels of this library do not match those from Cilium
// this will be used to convert the log levels.
type spiffeLogWrapper struct {
	log *slog.Logger
}

// newSpiffeLogWrapper returns a new spiffeLogWrapper
func newSpiffeLogWrapper(log *slog.Logger) *spiffeLogWrapper {
	return &spiffeLogWrapper{
		log: log,
	}
}

// Debugf logs a debug message
func (l *spiffeLogWrapper) Debugf(format string, args ...any) {
	l.log.Debug(fmt.Sprintf(format, args...))
}

// Infof logs an info message
func (l *spiffeLogWrapper) Infof(format string, args ...any) {
	l.log.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a warning message
func (l *spiffeLogWrapper) Warnf(format string, args ...any) {
	l.log.Warn(fmt.Sprintf(format, args...))
}

// Errorf logs an error message downgraded to a warning as in our case
// a connection error on startups is expected on initial start of the oprator
// while the SPIRE server is still starting up. Any errors given by spire will
// result in an error passed back to the function caller which then is logged
// as an error.
func (l *spiffeLogWrapper) Errorf(format string, args ...any) {
	l.log.Warn(fmt.Sprintf(format, args...))
}
