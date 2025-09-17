// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"k8s.io/client-go/tools/cache"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the global k8s watcher.
var Cell = cell.Module(
	"k8s-watcher",
	"K8s Watcher",

	cell.Provide(newK8sWatcher),
	cell.ProvidePrivate(newK8sPodWatcher),
	cell.Provide(newK8sCiliumNodeWatcher),
	cell.ProvidePrivate(newK8sEndpointsWatcher),
	cell.ProvidePrivate(newK8sCiliumEndpointsWatcher),
	cell.Provide(newK8sEventReporter),
)

type ResourceGroupFunc = func(logger *slog.Logger, cfg WatcherConfiguration) (resourceGroups, waitForCachesOnly []string)

type k8sWatcherParams struct {
	cell.In

	Logger *slog.Logger

	K8sEventReporter          *K8sEventReporter
	K8sPodWatcher             *K8sPodWatcher
	K8sCiliumNodeWatcher      *K8sCiliumNodeWatcher
	K8sEndpointsWatcher       *K8sEndpointsWatcher
	K8sCiliumEndpointsWatcher *K8sCiliumEndpointsWatcher

	AgentConfig *option.DaemonConfig

	Clientset         k8sClient.Clientset
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups
	ResourceGroupsFn  ResourceGroupFunc

	KVStoreClient kvstore.Client
}

type k8sWatcherOut struct {
	cell.Out

	K8sWatcher *K8sWatcher
	CiliumEndpointStore *cache.SharedIndexInformer
}

func newK8sWatcher(params k8sWatcherParams) k8sWatcherOut {
	w := newWatcher(
		params.Logger,
		params.ResourceGroupsFn,
		params.Clientset,
		params.K8sPodWatcher,
		params.K8sCiliumNodeWatcher,
		params.K8sEndpointsWatcher,
		params.K8sCiliumEndpointsWatcher,
		params.K8sEventReporter,
		params.K8sResourceSynced,
		params.K8sAPIGroups,
		params.AgentConfig,
		params.KVStoreClient,
	)
	wg := sync.WaitGroup{}
	cepStore := provideCiliumEndpointStore(context.TODO(), &wg, params.Clientset)
	// wg.Wait()
	w.logger.Info("CiliumEndpoint informer cache provided. Store :")
	w.logger.Info("CiliumEndpointStore nil status", slog.Bool("isNil", cepStore == nil))
	return k8sWatcherOut{K8sWatcher: w, CiliumEndpointStore: cepStore}
}
