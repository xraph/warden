// Package store defines the aggregate persistence interface. Each subsystem
// (role, permission, assignment, relation, policy, resourcetype, checklog)
// defines its own store interface. The composite Store composes them all.
// Backends: Postgres, SQLite, and Memory.
package store

import (
	"context"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// Store is the aggregate persistence interface.
// Each subsystem store is a composable interface — same pattern as ControlPlane.
// A single backend (postgres, sqlite, memory) implements all of them.
type Store interface {
	role.Store
	permission.Store
	assignment.Store
	relation.Store
	policy.Store
	resourcetype.Store
	checklog.Store

	// Migrate runs all schema migrations.
	Migrate(ctx context.Context) error

	// Ping checks database connectivity.
	Ping(ctx context.Context) error

	// Close closes the store connection.
	Close() error
}
