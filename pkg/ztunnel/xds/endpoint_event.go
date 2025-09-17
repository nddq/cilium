package xds

import (
	"fmt"
	"log/slog"
	"net/netip"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/workloadapi"

	"github.com/cilium/cilium/pkg/endpoint"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// EndpointEventCollection holds one or more EndpointEvent.
//
// This is useful for transforming sets of models to and from EndpointEvent
// representation.
type EndpointEventCollection []*EndpointEvent

// AppendEndpoints will add the provided endpoint.Endpoint(s) to the collection,
// transforming each into an EndpointEvent.
//
// Each endpoint.Endpoint in the eps slice will be associated with the provided
// EndpointEventType.
func (c *EndpointEventCollection) AppendEndpoints(t EndpointEventType, eps []*endpoint.Endpoint) {
	for _, ep := range eps {
		*c = append(*c, &EndpointEvent{Type: t, Endpoint: ep})
	}
}

func (c *EndpointEventCollection) AppendCiliumEndpoints(t EndpointEventType, eps []*cilium_api_v2.CiliumEndpoint) {
	for _, ep := range eps {
		*c = append(*c, &EndpointEvent{Type: t, Cep: ep})
	}
}

// ToDeltaDiscoveryResponse will create a singular xDS DeltaDiscoveryResponse
// given a EndpointEventCollection.
//
// Per the DeltaDiscoveryResponse API, CREATE event types are transformed into
// xDS Workload objects and embedded into an xDS Address type.
//
// REMOVE events simple appends the unique ID of the Endpoint in the RemovedResources
// field in the DeltaDiscoveryResponse.
//
// The returned DeltaDiscoveryResponse can be sent directly on a DeltaAggregatedResources
// stream.
func (c EndpointEventCollection) ToDeltaDiscoveryResponse() *v3.DeltaDiscoveryResponse {
	createResources := make([]*v3.Resource, 0)
	removedNames := make([]string, 0)
	for _, event := range c {
		switch event.Type {
		case CREATE:
			address, err := event.ToXDSAddress()
			if err != nil {
				continue
			}

			anyPBAddr, err := anypb.New(address)
			if err != nil {
				continue
			}

			// ztunnel uses a very stripped down representation of a Resource
			// see: https://github.com/istio/ztunnel/blob/58cf2a0f943ffc23c32d889018428ddfa6175144/src/xds/client.rs#L773
			res := &v3.Resource{
				Name:     event.K8sUID,
				Resource: anyPBAddr,
			}

			createResources = append(createResources, res)
		case REMOVED:
			removedNames = append(removedNames, event.K8sUID)
		case CREATE_CEP:
			address, err := event.ToXDSAddress()
			if err != nil {
				continue
			}

			anyPBAddr, err := anypb.New(address)
			if err != nil {
				continue
			}

			// ztunnel uses a very stripped down representation of a Resource
			// see: https://github.com/istio/ztunnel/blob/58cf2a0f943ffc23c32d889018428ddfa6175144/src/xds/client.rs#L773
			res := &v3.Resource{
				Name:     string(event.Cep.UID),
				Resource: anyPBAddr,
			}

			createResources = append(createResources, res)
		case REMOVED_CEP:
			removedNames = append(removedNames, string(event.Cep.UID))
		}
	}

	// create nonce from UUID
	nonce := uuid.New().String()
	resp := &v3.DeltaDiscoveryResponse{
		TypeUrl:          xdsTypeURLAddress,
		Resources:        createResources,
		RemovedResources: removedNames,
		Nonce:            nonce,
	}
	slog.Debug("Generated DeltaDiscoveryResponse", slog.String("resp", resp.String()))
	return resp
}

type EndpointEventType int

const (
	CREATE EndpointEventType = iota
	REMOVED
	CREATE_CEP
	REMOVED_CEP
)

// EndpointEvent is a thin wrapper around an embedded endpoint.Endpoint.
// The wrapper provides an additional EndpointEventType field that represents
// an event type for the embedded Endpoint.
type EndpointEvent struct {
	Type EndpointEventType
	//TODO(vmalla): Remove endpoint obj completely and use only CiliumEndpoint
	*endpoint.Endpoint
	Cep *cilium_api_v2.CiliumEndpoint
}

// ToXDSAddress transforms the embedded Endpoint into a XDS Address capable of
// being used in a DeltaDiscoveryResponse.
//
// This transformation is heavily opinionated for our ZTunnel integration, make
// note of the hard-coded values in the transform.
func (e *EndpointEvent) ToXDSAddress() (*workloadapi.Address, error) {
	ipAddresses := make([][]byte, 0)
	if e.Cep == nil {
		if e.GetPod() == nil {
			return nil, fmt.Errorf("cannot transform EndpointEvent to XDS Address, missing Pod information")
		}

		if e.IPv4.IsValid() {
			ipAddresses = append(ipAddresses, e.IPv4.AsSlice())
		}
		if e.IPv6.IsValid() {
			ipAddresses = append(ipAddresses, e.IPv6.AsSlice())

		}

		w := &workloadapi.Workload{
			Uid:            e.K8sUID,
			Node:           e.GetPod().Spec.NodeName,
			Name:           e.K8sPodName,
			Namespace:      e.K8sNamespace,
			ServiceAccount: e.GetPod().Spec.ServiceAccountName,
			TunnelProtocol: workloadapi.TunnelProtocol_HBONE,
			Addresses:      ipAddresses,
		}

		address := &workloadapi.Address{
			Type: &workloadapi.Address_Workload{
				Workload: w,
			},
		}

		return address, nil
	} else {
		slog.Debug("Transforming EndpointEvent to XDS Address", slog.String("eventType", fmt.Sprintf("%v", e)))
		// Use CiliumEndpoint information to create XDS Address
		// Prefer CiliumEndpoint over Endpoint if both are present
		// if e == nil  {
		// 	return nil, fmt.Errorf("cannot transform EndpointEvent to XDS Address, missing cep status information")
		// }

		//TODO(vmalla): Add proper validation for Addressing
		if e.Cep.Status.Networking.Addressing[0].IPV4 != "" {
			if ipv4, err := netip.ParseAddr(e.Cep.Status.Networking.Addressing[0].IPV4); err == nil && ipv4.IsValid() {
				ipAddresses = append(ipAddresses, ipv4.AsSlice())
			}
		}
		if e.Cep.Status.Networking.Addressing[0].IPV6 != "" {
			if ipv6, err := netip.ParseAddr(e.Cep.Status.Networking.Addressing[0].IPV6); err == nil && ipv6.IsValid() {
				ipAddresses = append(ipAddresses, ipv6.AsSlice())
			}
		}

		w := &workloadapi.Workload{
			Uid:            string(e.Cep.UID),
			Node:           e.Cep.Status.Networking.NodeIP,
			Name:           e.Cep.GetObjectMeta().GetName(),
			Namespace:      e.Cep.GetObjectMeta().GetNamespace(),
			ServiceAccount: e.Cep.Status.ServiceAccount,
			TunnelProtocol: workloadapi.TunnelProtocol_HBONE,
			Addresses:      ipAddresses,
		}

		address := &workloadapi.Address{
			Type: &workloadapi.Address_Workload{
				Workload: w,
			},
		}

		return address, nil
	}

}
