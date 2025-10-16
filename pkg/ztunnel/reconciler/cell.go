// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/table"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"enrollment-reconciler",
	"Reconciler for namespace enrollment for ztunnel mTLS",
	cell.Provide(
		table.NewEnrolledNamespacesTable,
		NewEnrollmentReconciler,
	),
	cell.Invoke(statedb.Derive("derive-desired-mtls-namespace-enrollments", defaultNamespaceToEnrolledNamespace)),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*table.EnrolledNamespace],
	tbl statedb.RWTable[*table.EnrolledNamespace],
	cfg config.Config,
) error {
	if !cfg.EnableZTunnel {
		return nil
	}
	_, err := reconciler.Register(
		params,
		tbl,
		(*table.EnrolledNamespace).Clone,
		(*table.EnrolledNamespace).SetStatus,
		(*table.EnrolledNamespace).GetStatus,
		ops,
		nil, // no batch operations support
		reconciler.WithoutPruning(),
	)
	if err != nil {
		return err
	}
	return nil
}

func defaultNamespaceToEnrolledNamespace(ns k8s.Namespace, deleted bool) (*table.EnrolledNamespace, statedb.DeriveResult) {
	enrolled := true
	if mtlsValue, exists := ns.Labels["mtls-enabled"]; !exists || mtlsValue != "true" {
		enrolled = false
	}
	if deleted || !enrolled {
		return &table.EnrolledNamespace{
			Name:   ns.Name,
			Status: reconciler.StatusPending(),
		}, statedb.DeriveDelete
	}
	return &table.EnrolledNamespace{
		Name:   ns.Name,
		Status: reconciler.StatusPending(),
	}, statedb.DeriveInsert
}
