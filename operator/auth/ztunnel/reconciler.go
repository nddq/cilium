// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"context"
	"iter"
	"log/slog"

	"github.com/cilium/cilium/operator/auth/ztunnel/certificateauthority"
	"github.com/cilium/cilium/operator/auth/ztunnel/namespaces"
	"github.com/cilium/cilium/operator/auth/ztunnel/serviceaccounts"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

type params struct {
	cell.In

	DB                     *statedb.DB
	ServiceAccountTable    statedb.Table[serviceaccounts.ServiceAccount]
	EnrolledNamespaceTable statedb.RWTable[*namespaces.Namespace]
	CAClient               certificateauthority.Client
	Logger                 *slog.Logger
	Lifecycle              cell.Lifecycle
}

type EnrollmentReconciler struct {
	db                     *statedb.DB
	logger                 *slog.Logger
	caClient               certificateauthority.Client
	serviceAccountTable    statedb.Table[serviceaccounts.ServiceAccount]
	enrolledNamespaceTable statedb.RWTable[*namespaces.Namespace]
}

func NewEnrollmentReconciler(cfg params) reconciler.Operations[*namespaces.Namespace] {
	ops := &EnrollmentReconciler{
		logger:                 cfg.Logger,
		caClient:               cfg.CAClient,
		db:                     cfg.DB,
		serviceAccountTable:    cfg.ServiceAccountTable,
		enrolledNamespaceTable: cfg.EnrolledNamespaceTable,
	}
	cfg.Lifecycle.Append(ops)
	return ops
}

func (ops *EnrollmentReconciler) Delete(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *namespaces.Namespace) error {
	if ns.Enrolled {
		// Namespace was enrolled, remove all service accounts in the namespace from the CA.
		sas := ops.serviceAccountTable.List(txn, serviceaccounts.NamespaceIndex.Query(ns.Name))
		entries := []*certificateauthority.ID{}
		for sa := range sas {
			entries = append(entries, &certificateauthority.ID{
				Namespace:      sa.Namespace,
				ServiceAccount: sa.Name,
			})
		}
		if len(entries) == 0 {
			ops.logger.Info("No service accounts found in deleted enrolled namespace", slog.String("namespace", ns.Name))
			return nil
		}
		err := ops.caClient.Delete(context.Background(), entries...)
		if err != nil {
			ops.logger.Error("failed to delete CA entries for deleted enrolled namespace", slog.String("namespace", ns.Name), slog.String("error", err.Error()))
			return err
		}
		ops.logger.Info("Deleted CA entries for deleted enrolled namespace", slog.String("namespace", ns.Name), slog.Int("serviceaccounts", len(entries)))
	}
	return nil
}

// Prune unexpected entries.
func (ops *EnrollmentReconciler) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*namespaces.Namespace, statedb.Revision]) error {
	return nil
}

func (ops *EnrollmentReconciler) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *namespaces.Namespace) error {
	ops.logger.Debug("Reconciling namespace", slog.String("namespace", ns.Name), slog.Bool("currentlyEnrolled", ns.Enrolled), slog.Bool("previouslyEnrolled", ns.PendingCADeletion))
	if ns.PendingCADeletion {
		sas := ops.serviceAccountTable.List(txn, serviceaccounts.NamespaceIndex.Query(ns.Name))
		entries := []*certificateauthority.ID{}
		for sa := range sas {
			entries = append(entries, &certificateauthority.ID{
				Namespace:      sa.Namespace,
				ServiceAccount: sa.Name,
			})
		}
		if len(entries) == 0 {
			ops.logger.Info("No service accounts found in unenrolled namespace", slog.String("namespace", ns.Name))
			return nil
		}
		err := ops.caClient.Delete(context.Background(), entries...)
		if err != nil {
			ops.logger.Error("failed to delete CA entries for unenrolled namespace", slog.String("namespace", ns.Name), slog.String("error", err.Error()))
			return err
		}
		ops.logger.Info("Deleted CA entries for unenrolled namespace", slog.String("namespace", ns.Name), slog.Int("serviceaccounts", len(entries)))
		ns.PendingCADeletion = false
		return nil
	} else {
		if !ns.PendingCACreation {
			// Namespace was not previously enrolled and is still not enrolled.
			// Nothing to do.
			return nil
		}
		// Namespace is enrolled, nsure all service accounts in the namespace are
		// present in the CA.
		sas := ops.serviceAccountTable.List(txn, serviceaccounts.NamespaceIndex.Query(ns.Name))
		entries := []*certificateauthority.ID{}
		for sa := range sas {
			entries = append(entries, &certificateauthority.ID{
				Namespace:      sa.Namespace,
				ServiceAccount: sa.Name,
			})
		}
		if len(entries) == 0 {
			ops.logger.Info("No service accounts found in enrolled namespace", slog.String("namespace", ns.Name))
			return nil
		}
		err := ops.caClient.Upsert(context.Background(), entries...)
		if err != nil {
			ops.logger.Error("failed to upsert CA entries for enrolled namespace", slog.String("namespace", ns.Name), slog.String("error", err.Error()))
			return err
		}
		ops.logger.Info("Upserted CA entries for enrolled namespace", slog.String("namespace", ns.Name), slog.Int("serviceaccounts", len(entries)))
		ns.PendingCACreation = false
		return nil
	}
}

var _ reconciler.Operations[*namespaces.Namespace] = &EnrollmentReconciler{}

func (ops *EnrollmentReconciler) Start(ctx cell.HookContext) error {
	err := ops.caClient.Initialize(ctx)
	if err != nil {
		ops.logger.Error("failed to initialize CA client", slog.String("error", err.Error()))
		return err
	}
	_, initialized := ops.serviceAccountTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("ServiceAccount table initialized")
	_, initialized = ops.enrolledNamespaceTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("EnrolledNamespace table initialized")
	go func() {
		// Start watching for changes in the ServiceAccount table.
		ops.logger.Info("Starting mTLS enrollment reconciler")
		wtxn := ops.db.WriteTxn(ops.serviceAccountTable)
		changeIterator, err := ops.serviceAccountTable.Changes(wtxn)
		wtxn.Commit()
		if err != nil {
			ops.logger.Error("failed to create change iterator", slog.String("error", err.Error()))
			return
		}
		for {
			changes, watch := changeIterator.Next(ops.db.ReadTxn())
			for change := range changes {
				sa := change.Object
				if change.Deleted {
					ops.logger.Debug("ServiceAccount deleted", slog.String("name", sa.Name))
					id := &certificateauthority.ID{
						Namespace:      sa.Namespace,
						ServiceAccount: sa.Name,
					}
					err := ops.caClient.Delete(context.Background(), id)
					if err != nil {
						ops.logger.Error("failed to delete CA entry", slog.String("error", err.Error()), slog.String("id", id.String()))
					} else {
						ops.logger.Info("CA entry deleted", slog.String("id", id.String()))
					}
				} else {
					ops.logger.Debug("ServiceAccount added/updated", slog.String("name", sa.Name))
					// Check if the service account belongs to an enrolled namespace
					// by query the namespace table.
					ns, _, found := ops.enrolledNamespaceTable.Get(ops.db.ReadTxn(), namespaces.EnrolledNamespacesNameIndex.Query(sa.Namespace))
					if !found {
						ops.logger.Error("Namespace not found", slog.String("namespace", sa.Namespace))
						continue
					}
					if !ns.Enrolled {
						ops.logger.Debug("Namespace not enrolled for mTLS", slog.String("namespace", sa.Namespace))
						continue
					}
					// Upsert the CA entry.
					id := &certificateauthority.ID{
						Namespace:      sa.Namespace,
						ServiceAccount: sa.Name,
					}
					err := ops.caClient.Upsert(context.Background(), id)
					if err != nil {
						ops.logger.Error("failed to upsert CA entry", slog.String("error", err.Error()), slog.String("id", id.String()))
					} else {
						ops.logger.Info("CA entry upserted", slog.String("id", id.String()))
					}
				}
			}
			<-watch
		}
	}()
	return nil
}

func (ops *EnrollmentReconciler) Stop(cell.HookContext) error {
	ops.logger.Info("Stopping reconciler")
	return nil
}

var _ cell.HookInterface = &EnrollmentReconciler{}
