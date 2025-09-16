// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/operator/auth/ztunnel/config"
	"github.com/cilium/cilium/operator/auth/ztunnel/namespaces"
	"github.com/cilium/cilium/operator/auth/ztunnel/serviceaccounts"
	"github.com/cilium/cilium/operator/auth/ztunnel/spire"
)

var Cell = cell.Module(
	"ztunnel",
	"Provides ztunnel mTLS integration",
	cell.Config(spire.DefaultClientConfig),
	cell.Config(config.DefaultZtunnelConfig),
	cell.Provide(reconciler.NewExpVarMetrics),
	cell.Provide(
		NewEnrollmentReconciler,
		namespaces.NewEnrolledNamespacesTable,
		spire.NewClient,
		serviceaccounts.NewServiceAccountTable,
	),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	ztunnelCfg config.ZtunnelConfig,
	params reconciler.Params,
	ops reconciler.Operations[*namespaces.Namespace],
	tbl statedb.RWTable[*namespaces.Namespace],
	m *reconciler.ExpVarMetrics,
) error {
	if !ztunnelCfg.Enabled {
		return nil
	}
	_, err := reconciler.Register(
		params,
		tbl,
		(*namespaces.Namespace).Clone,
		(*namespaces.Namespace).SetStatus,
		(*namespaces.Namespace).GetStatus,
		ops,
		nil, // no batch operations support

		reconciler.WithMetrics(m),
		reconciler.WithPruning(time.Minute),
		reconciler.WithRefreshing(time.Minute, nil),
	)
	if err != nil {
		return err
	}
	return nil
}
