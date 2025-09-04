// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	hubblemetrics "github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type k8sCiliumEndpointsWatcherParams struct {
	cell.In

	Logger *slog.Logger

	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	EndpointManager     endpointmanager.EndpointManager
	PolicyUpdater       *policy.Updater
	IPCache             *ipcache.IPCache
	WgConfig            wgTypes.WireguardConfig
	CiliumEndpointStore cache.Indexer
}

func newK8sCiliumEndpointsWatcher(params k8sCiliumEndpointsWatcherParams) *K8sCiliumEndpointsWatcher {
	return &K8sCiliumEndpointsWatcher{
		logger:              params.Logger,
		k8sResourceSynced:   params.K8sResourceSynced,
		k8sAPIGroups:        params.K8sAPIGroups,
		resources:           params.Resources,
		endpointManager:     params.EndpointManager,
		policyManager:       params.PolicyUpdater,
		ipcache:             params.IPCache,
		wgConfig:            params.WgConfig,
		CiliumEndpointStore: params.CiliumEndpointStore,
	}
}

type K8sCiliumEndpointsWatcher struct {
	logger *slog.Logger
	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups

	endpointManager     endpointManager
	policyManager       policyManager
	ipcache             ipcacheManager
	wgConfig            wgTypes.WireguardConfig
	CiliumEndpointStore cache.Indexer

	resources agentK8s.Resources
}

// initCiliumEndpointOrSlices initializes the ciliumEndpoints or ciliumEndpointSlice
func (k *K8sCiliumEndpointsWatcher) initCiliumEndpointOrSlices(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	// If CiliumEndpointSlice feature is enabled, Cilium-agent watches CiliumEndpointSlice
	// objects instead of CiliumEndpoints. Hence, skip watching CiliumEndpoints if CiliumEndpointSlice
	// feature is enabled.
	if option.Config.EnableCiliumEndpointSlice {
		k.ciliumEndpointSliceInit(ctx)
	} else {
		k.ciliumEndpointsInit(ctx, wg, clientset)
	}
}

var errNoCE = errors.New("object is not a *cilium_api_v2.CiliumEndpoint")

// identityIndexFunc index identities by ID.
func identityIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *cilium_api_v2.CiliumEndpoint:
		if t.Status.Identity != nil {
			id := strconv.FormatInt(t.Status.Identity.ID, 10)
			return []string{id}, nil
		}
		return []string{"0"}, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoCE, obj)
}

// transformToCiliumEndpoint transforms a CiliumEndpoint to a minimal CiliumEndpoint
// containing only a minimal set of entities used to identity a CiliumEndpoint
// Warning: The CiliumEndpoints created by the converter are not intended to be
// used for Update operations in k8s. If the given obj can't be cast into either
// CiliumEndpoint nor DeletedFinalStateUnknown, an error is returned.
func transformToCiliumEndpoint(obj any) (any, error) {
	switch concreteObj := obj.(type) {
	case *cilium_api_v2.CiliumEndpoint:
		p := &cilium_api_v2.CiliumEndpoint{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
				OwnerReferences: concreteObj.OwnerReferences,
				UID:             concreteObj.UID,
			},
			Status: cilium_api_v2.EndpointStatus{
				Identity:   concreteObj.Status.Identity,
				Networking: concreteObj.Status.Networking,
				NamedPorts: concreteObj.Status.NamedPorts,
				Encryption: concreteObj.Status.Encryption,
			},
		}
		*concreteObj = cilium_api_v2.CiliumEndpoint{}
		return p, nil
	case cache.DeletedFinalStateUnknown:
		ciliumEndpoint, ok := concreteObj.Obj.(*cilium_api_v2.CiliumEndpoint)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &cilium_api_v2.CiliumEndpoint{
				TypeMeta: ciliumEndpoint.TypeMeta,
				ObjectMeta: metav1.ObjectMeta{
					Name:            ciliumEndpoint.Name,
					Namespace:       ciliumEndpoint.Namespace,
					ResourceVersion: ciliumEndpoint.ResourceVersion,
					OwnerReferences: ciliumEndpoint.OwnerReferences,
					UID:             ciliumEndpoint.UID,
				},
				Status: cilium_api_v2.EndpointStatus{
					Identity:   ciliumEndpoint.Status.Identity,
					Networking: ciliumEndpoint.Status.Networking,
					NamedPorts: ciliumEndpoint.Status.NamedPorts,
					Encryption: ciliumEndpoint.Status.Encryption,
				},
			},
		}
		// Small GC optimization
		*ciliumEndpoint = cilium_api_v2.CiliumEndpoint{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func (k *K8sCiliumEndpointsWatcher) ciliumEndpointsInit(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	var synced atomic.Bool
	const identityIndex = "identity"
	var (
		indexers = cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			identityIndex:        identityIndexFunc,
		}

		// CiliumEndpointStore contains all CiliumEndpoint present in k8s.
		// Warning: The CiliumEndpoints stored in the cache are not intended to be
		// used for Update operations in k8s as some of its fields were are not
		// populated.
		CiliumEndpointStore cache.Indexer

		// CiliumEndpointsSynced is closed once the CiliumEndpointStore is synced
		// with k8s.
		CiliumEndpointsSynced = make(chan struct{})
		// once is used to make sure CiliumEndpointsInit is only setup once.
		once sync.Once
	)

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		ctx.Done(),
		nil,
		func() bool { return synced.Load() },
		k8sAPIGroupCiliumEndpointV2,
	)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointV2)

	go func() {
		events := k.resources.CiliumSlimEndpoint.Events(ctx)
		cache := make(map[resource.Key]*types.CiliumEndpoint)
		for event := range events {
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
			case resource.Upsert:
				oldObj, ok := cache[event.Key]
				if !ok || !oldObj.DeepEqual(event.Object) {
					k.endpointUpdated(oldObj, event.Object)
					cache[event.Key] = event.Object
				}
			case resource.Delete:
				k.endpointDeleted(event.Object)
				delete(cache, event.Key)
			}
			event.Done(nil)
		}
	}()

	once.Do(func() {
		CiliumEndpointStore = cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, indexers)

		ciliumEndpointInformer := informer.NewInformerWithStore(
			utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](clientset.CiliumV2().CiliumEndpoints("")),
			&cilium_api_v2.CiliumEndpoint{},
			0,
			cache.ResourceEventHandlerFuncs{},
			transformToCiliumEndpoint,
			CiliumEndpointStore,
		)

		wg.Add(1)
		go func() {
			defer wg.Done()
			ciliumEndpointInformer.Run(ctx.Done())
		}()

		cache.WaitForCacheSync(ctx.Done(), ciliumEndpointInformer.HasSynced)
		close(CiliumEndpointsSynced)
	})
}

func (k *K8sCiliumEndpointsWatcher) endpointUpdated(oldEndpoint, endpoint *types.CiliumEndpoint) {
	var namedPortsChanged bool
	defer func() {
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates("Named ports added or updated")
		}
	}()
	var ipsAdded []string
	if oldEndpoint != nil && oldEndpoint.Networking != nil {
		// Delete the old IP addresses from the IP cache
		defer func() {
			for _, oldPair := range oldEndpoint.Networking.Addressing {
				v4Added, v6Added := false, false
				for _, ipAdded := range ipsAdded {
					if ipAdded == oldPair.IPV4 {
						v4Added = true
					}
					if ipAdded == oldPair.IPV6 {
						v6Added = true
					}
				}
				if !v4Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
				if !v6Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
			}
		}()
	}

	// default to the standard key
	encryptionKey := node.GetEndpointEncryptKeyIndex(k.logger, k.wgConfig)

	id := identity.ReservedIdentityUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
	}

	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	if endpoint.Networking == nil || endpoint.Networking.NodeIP == "" {
		k.logger.Warn("NodeIP not available", logfields.Identity, id)
		// When upgrading from an older version, the nodeIP may
		// not be available yet in the CiliumEndpoint and we
		// have to wait for it to be propagated
		return
	}

	nodeIP := net.ParseIP(endpoint.Networking.NodeIP)
	if nodeIP == nil {
		k.logger.Warn(
			"Unable to parse node IP while processing CiliumEndpoint update",
			logfields.NodeIP, endpoint.Networking.NodeIP,
		)
		return
	}

	k8sMeta := &ipcache.K8sMetadata{
		Namespace:  endpoint.Namespace,
		PodName:    endpoint.Name,
		NamedPorts: make(ciliumTypes.NamedPortMap, len(endpoint.NamedPorts)),
	}
	for _, port := range endpoint.NamedPorts {
		p, err := u8proto.ParseProtocol(port.Protocol)
		if err != nil {
			k.logger.Error(
				"Parsing named port protocol failed",
				logfields.Error, err,
				logfields.CEPName, endpoint.GetName(),
			)
			continue
		}
		k8sMeta.NamedPorts[port.Name] = ciliumTypes.PortProto{
			Port:  port.Port,
			Proto: p,
		}
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ipsAdded = append(ipsAdded, pair.IPV4)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}

		if pair.IPV6 != "" {
			ipsAdded = append(ipsAdded, pair.IPV6)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}
	}
}

func (k *K8sCiliumEndpointsWatcher) endpointDeleted(endpoint *types.CiliumEndpoint) {
	if endpoint.Networking != nil {
		namedPortsChanged := false
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates("Named ports deleted")
		}
	}
	hubblemetrics.ProcessCiliumEndpointDeletion(endpoint)
}
