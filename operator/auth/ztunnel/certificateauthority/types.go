// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certificateauthority

import (
	"context"
	"fmt"
)

type Client interface {
	Initialize(ctx context.Context) error
	Upsert(ctx context.Context, ids ...*ID) error
	Delete(ctx context.Context, ids ...*ID) error
}

type ID struct {
	Namespace      string
	ServiceAccount string
}

func (c ID) String() string {
	return fmt.Sprintf("/ns/%s/sa/%s", c.Namespace, c.ServiceAccount)
}
