package maps

import (
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
)

var log = logging.DefaultSlogLogger

func GetEndpointMetadata(ipAddr net.IP) (lxcmap.EndpointInfo, error) {
	lxcMap, err := lxcmap.LoadMap(log)
	if err != nil {
		log.Error("Cannot load lxc bpf map", logfields.Error, err)
		return lxcmap.EndpointInfo{}, err
	}

	endpointInfo, err := lxcMap.Get(*lxcmap.NewEndpointKey(ipAddr))
	if err != nil {
		log.Error("Cannot load value from lxc bpf map", logfields.IPAddr, ipAddr, logfields.Error, err)
		return lxcmap.EndpointInfo{}, err
	}
	log.Debug("Endpoint info from lxc bpf map", logfields.Endpoint, endpointInfo)

	return endpointInfo, nil
}

func GetIdentity(ipAddr netip.Addr) (ipcache.RemoteEndpointInfo, error) {
	ip := net.ParseIP(ipAddr.String())
	clusterId := uint16(0)       // for non cluster mesh
	mask := net.CIDRMask(32, 32) // for IPv4, 32 bits for the network

	if ip.To16() != nil {
		mask = net.CIDRMask(128, 128) // for IPv6, 128 bits for the network
	}

	ipcacheMap, err := ipcache.LoadMap(log)
	if err != nil {
		log.Error("Cannot load config ipcache bpf map", logfields.Error, err)
		return ipcache.RemoteEndpointInfo{}, err
	}

	identityInfo, err := ipcacheMap.Get(ipcache.NewKey(ip, mask, clusterId))
	if err != nil {
		log.Error("Cannot load value from ipcache bpf map", logfields.IPAddr, ipAddr, logfields.Error, err)
		// Check local cache for identity info
		if identityInfo, ok := GetLocalIdentityInfo(ipAddr.String()); ok {
			log.Debug("Identity info from local cache", logfields.Identity, identityInfo)
			return identityInfo, nil
		}
		return ipcache.RemoteEndpointInfo{}, err
	}
	log.Debug("Identity info from ipcache bpf map", logfields.Identity, identityInfo)

	// Cache the identity info
	SetLocalIdentityInfo(ipAddr.String(), identityInfo)
	return identityInfo, nil
}
