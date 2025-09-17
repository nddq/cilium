// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/daemon/k8s"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"enrollment-reconciler",
	"Reconciler for namespace enrollment for ztunnel mTLS",
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*Namespace],
	tbl statedb.RWTable[*Namespace],
	deriveParams statedb.DeriveParams[k8s.Namespace, *Namespace],
) error {
	// Start deriving Table[*Namespace] from Table[*k8s.Namespace]
	statedb.Derive("derive-desired-mtls-namespace-enrollments", defaultNamespaceToEnrolledNamespace)(
		deriveParams,
	)
	_, err := reconciler.Register(
		params,
		tbl,
		(*Namespace).Clone,
		(*Namespace).SetStatus,
		(*Namespace).GetStatus,
		ops,
		nil, // no batch operations support
		reconciler.WithoutPruning(),
	)
	if err != nil {
		return err
	}
	return nil
}

func defaultNamespaceToEnrolledNamespace(ns k8s.Namespace, deleted bool) (*Namespace, statedb.DeriveResult) {
	enrolled := true
	if mtlsValue, exists := ns.Labels["mtls-enabled"]; !exists || mtlsValue != "true" {
		enrolled = false
	}
	if deleted {
		return &Namespace{
			Name:     ns.Name,
			Enrolled: enrolled,
			Status:   reconciler.StatusPending(),
		}, statedb.DeriveDelete
	}
	return &Namespace{
		Name:     ns.Name,
		Enrolled: enrolled,
		Status:   reconciler.StatusPending(),
	}, statedb.DeriveInsert
}
