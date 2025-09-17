// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type Namespace struct {
	Name string // Name is the name of the namespace.
	// Enrolled indicates if the namespace is enrolled for mTLS.
	Enrolled bool
	Status   reconciler.Status // reconciliation status
}

// TableHeader implements statedb.TableWritable.
func (ns *Namespace) TableHeader() []string {
	return []string{"Name", "Enrolled for mTLS", "Status"}
}

// TableRow implements statedb.TableWritable.
func (ns *Namespace) TableRow() []string {
	return []string{ns.Name, fmt.Sprintf("%t", ns.Enrolled), ns.Status.String()}
}

var _ statedb.TableWritable = &Namespace{}

// GetStatus returns the reconciliation status. Used to provide the
// reconciler access to it.
func (ns Namespace) GetStatus() reconciler.Status {
	return ns.Status
}

// SetStatus sets the reconciliation status.
// Used by the reconciler to update the reconciliation status of the EnrolledNamespace.
func (ns *Namespace) SetStatus(status reconciler.Status) *Namespace {
	ns.Status = status
	return ns
}

// Clone returns a shallow copy of the EnrolledNamespace.
func (ns *Namespace) Clone() *Namespace {
	e := *ns
	return &e
}

// EnrolledNamespacesNameIndex allows looking up EnrolledNamespace by its name.
var EnrolledNamespacesNameIndex = statedb.Index[*Namespace, string]{
	Name: "name",
	FromObject: func(ns *Namespace) index.KeySet {
		return index.NewKeySet(index.String(ns.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

func NewEnrolledNamespacesTable(db *statedb.DB) (statedb.RWTable[*Namespace], error) {
	return statedb.NewTable(
		db,
		"mtls-enrolled-namespaces",
		EnrolledNamespacesNameIndex,
	)
}
