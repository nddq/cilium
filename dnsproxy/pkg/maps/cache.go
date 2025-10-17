package maps

import (
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

type localIdentity struct {
	identityInfo map[string]ipcache.RemoteEndpointInfo
	mu           lock.RWMutex
}

func (s *localIdentity) GetIdentityInfo(key string) (ipcache.RemoteEndpointInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, exists := s.identityInfo[key]
	return value, exists
}

func (s *localIdentity) SetIdentityInfo(key string, value ipcache.RemoteEndpointInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityInfo[key] = value
}

// Local cache
var localIdentityCache localIdentity

func Init() {
	localIdentityCache = localIdentity{
		identityInfo: make(map[string]ipcache.RemoteEndpointInfo, 1000),
	}
}

func GetLocalIdentityInfo(key string) (ipcache.RemoteEndpointInfo, bool) {
	return localIdentityCache.GetIdentityInfo(key)
}

func SetLocalIdentityInfo(key string, value ipcache.RemoteEndpointInfo) {
	localIdentityCache.SetIdentityInfo(key, value)
}
