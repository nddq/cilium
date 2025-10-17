package dns

import (
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type SelectorRules struct {
	Selection      []uint32
	Rules          []api.PortRuleDNS
	Key            string
	MetadataLabels labels.LabelArray
}

func (s *SelectorRules) GetSelections(_ *versioned.VersionHandle) identity.NumericIdentitySlice {
	selections := make(identity.NumericIdentitySlice, len(s.Selection))
	for i, val := range s.Selection {
		selections[i] = identity.NumericIdentity(val)
	}
	return selections
}

func (s *SelectorRules) Selects(_ *versioned.VersionHandle, nid identity.NumericIdentity) bool {
	if s.IsWildcard() {
		return true
	}
	for _, s := range s.Selection {
		if s == nid.Uint32() {
			return true
		}
	}
	return false
}

func (s *SelectorRules) IsWildcard() bool {
	return s.Key == api.WildcardEndpointSelector.LabelSelector.String()
}

func (s *SelectorRules) IsNone() bool {
	return s.Key == api.EndpointSelectorNone.LabelSelector.String()
}

func (s *SelectorRules) String() string {
	return s.Key
}

func (s *SelectorRules) GetMetadataLabels() labels.LabelArray {
	return s.MetadataLabels
}
