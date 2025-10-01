// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	_ "embed"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/pflag"

	ztunnelReconciler "github.com/cilium/cilium/pkg/ztunnel/reconciler"
)

var DefaultConfig = Config{
	EnableZTunnel: false,
}

type Config struct {
	EnableZTunnel bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
}

// Cell manages the ztunnel DaemonSet, ensuring a ztunnel proxy runs on each
// node in the cluster when ztunnel encryption is enabled.
var Cell = cell.Module(
	"ztunnel",
	"ZTunnel DaemonSet Controller",

	cell.Config(DefaultConfig),
	cell.Provide(reconciler.NewExpVarMetrics),
	cell.Provide(
		ztunnelReconciler.NewEnrolledNamespacesTable,
		NewEnrollmentReconciler,
		NewServiceAccountTable,
		newZtunnelSpireClient,
	),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	cfg Config,
	params reconciler.Params,
	ops reconciler.Operations[*ztunnelReconciler.Namespace],
	tbl statedb.RWTable[*ztunnelReconciler.Namespace],
	m *reconciler.ExpVarMetrics,
) error {
	if !cfg.EnableZTunnel {
		return nil
	}
	_, err := reconciler.Register(
		params,
		tbl,
		(*ztunnelReconciler.Namespace).Clone,
		(*ztunnelReconciler.Namespace).SetStatus,
		(*ztunnelReconciler.Namespace).GetStatus,
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
