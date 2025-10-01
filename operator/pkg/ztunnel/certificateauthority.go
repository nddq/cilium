package ztunnel

import (
	"context"
	"fmt"
)

type CAClient interface {
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
