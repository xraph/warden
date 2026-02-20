// Package plugin defines the plugin system for Warden.
// Plugins are notified of lifecycle events (check performed, role created,
// policy updated, etc.) and can react — logging, metrics, tracing, etc.
//
// Each lifecycle hook is a separate interface so plugins opt in only
// to the events they care about.
package plugin

import (
	"context"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
)

// Plugin is the base interface all plugins must implement.
type Plugin interface {
	// Name returns a unique human-readable name for the plugin.
	Name() string
}

// ──────────────────────────────────────────────────
// Check lifecycle hooks
// ──────────────────────────────────────────────────

// BeforeCheck is called before an authorization check is evaluated.
// The req parameter is *warden.CheckRequest (passed as any to avoid import cycle).
type BeforeCheck interface {
	OnBeforeCheck(ctx context.Context, req any) error
}

// AfterCheck is called after an authorization check completes.
// The req parameter is *warden.CheckRequest; result is *warden.CheckResult.
type AfterCheck interface {
	OnAfterCheck(ctx context.Context, req, result any) error
}

// ──────────────────────────────────────────────────
// Role lifecycle hooks
// ──────────────────────────────────────────────────

// RoleCreated is called after a role is created.
type RoleCreated interface {
	OnRoleCreated(ctx context.Context, r *role.Role) error
}

// RoleUpdated is called after a role is updated.
type RoleUpdated interface {
	OnRoleUpdated(ctx context.Context, r *role.Role) error
}

// RoleDeleted is called after a role is deleted.
type RoleDeleted interface {
	OnRoleDeleted(ctx context.Context, roleID id.RoleID) error
}

// ──────────────────────────────────────────────────
// Permission lifecycle hooks
// ──────────────────────────────────────────────────

// PermissionCreated is called after a permission is created.
type PermissionCreated interface {
	OnPermissionCreated(ctx context.Context, p *permission.Permission) error
}

// PermissionDeleted is called after a permission is deleted.
type PermissionDeleted interface {
	OnPermissionDeleted(ctx context.Context, permID id.PermissionID) error
}

// PermissionAttached is called after a permission is attached to a role.
type PermissionAttached interface {
	OnPermissionAttached(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error
}

// PermissionDetached is called after a permission is detached from a role.
type PermissionDetached interface {
	OnPermissionDetached(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error
}

// ──────────────────────────────────────────────────
// Assignment lifecycle hooks
// ──────────────────────────────────────────────────

// RoleAssigned is called after a role is assigned to a subject.
type RoleAssigned interface {
	OnRoleAssigned(ctx context.Context, a *assignment.Assignment) error
}

// RoleUnassigned is called after a role is unassigned from a subject.
type RoleUnassigned interface {
	OnRoleUnassigned(ctx context.Context, a *assignment.Assignment) error
}

// ──────────────────────────────────────────────────
// Relation lifecycle hooks
// ──────────────────────────────────────────────────

// RelationWritten is called after a relation tuple is written.
type RelationWritten interface {
	OnRelationWritten(ctx context.Context, t *relation.Tuple) error
}

// RelationDeleted is called after a relation tuple is deleted.
type RelationDeleted interface {
	OnRelationDeleted(ctx context.Context, relID id.RelationID) error
}

// ──────────────────────────────────────────────────
// Policy lifecycle hooks
// ──────────────────────────────────────────────────

// PolicyCreated is called after a policy is created.
type PolicyCreated interface {
	OnPolicyCreated(ctx context.Context, p *policy.Policy) error
}

// PolicyUpdated is called after a policy is updated.
type PolicyUpdated interface {
	OnPolicyUpdated(ctx context.Context, p *policy.Policy) error
}

// PolicyDeleted is called after a policy is deleted.
type PolicyDeleted interface {
	OnPolicyDeleted(ctx context.Context, polID id.PolicyID) error
}

// ──────────────────────────────────────────────────
// Shutdown hook
// ──────────────────────────────────────────────────

// Shutdown is called during graceful shutdown.
type Shutdown interface {
	OnShutdown(ctx context.Context) error
}
