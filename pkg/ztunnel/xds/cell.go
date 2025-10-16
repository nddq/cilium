// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

var Cell = cell.Module(
	"ztunnel-xds",
	"ztunnel certificate authority and control plane",
	cell.Provide(NewServer),
	cell.Provide(func(x *Server) chan *EndpointEvent {
		if x != nil {
			return x.EndpointEventChannel()
		}
		return nil
	}),
)

type xdsServerParams struct {
	cell.In

	Lifecycle              cell.Lifecycle
	Logger                 *slog.Logger
	EPManager              endpointmanager.EndpointManager
	DB                     *statedb.DB
	EnrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	K8sWatcher             *watchers.K8sWatcher
	Config                 config.Config
}

func NewServer(params xdsServerParams) *Server {
	if !params.Config.EnableZTunnel {
		return nil
	}

	server := &Server{
		log:                       params.Logger,
		k8sCiliumEndpointsWatcher: params.K8sWatcher.GetK8sCiliumEndpointsWatcher(),
		epManager:                 params.EPManager,
		enrolledNamespaceTable:    params.EnrolledNamespaceTable,
		endpointEventChan:         make(chan *EndpointEvent, 1024),
		db:                        params.DB,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			if err := server.Serve(); err != nil {
				params.Logger.Error("failed to start ztunnel gRPC server", logfields.Error, err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			server.GracefulStop()
			return nil
		},
	})

	return server
}
