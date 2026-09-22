package role

import (
	"context"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
)

// Store defines persistence operations for roles.
//
// Every by-ID operation takes the tenant as a mandatory parameter and
// filters on it alongside the primary key. A call whose tenant does not own
// the row behaves exactly as if the row did not exist: reads and writes
// return ErrRoleNotFound, and nothing on disk changes.
type Store interface {
	// CreateRole persists a new role.
	CreateRole(ctx context.Context, r *Role) error

	// GetRole retrieves a role by ID within a tenant.
	GetRole(ctx context.Context, tenantID string, roleID id.RoleID) (*Role, error)

	// GetRoles retrieves several roles by ID within a tenant in one round
	// trip. IDs that do not exist, or belong to another tenant, are omitted
	// from the result rather than reported as an error. Order is undefined.
	GetRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) ([]*Role, error)

	// GetRoleBySlug retrieves a role by tenant, namespace, and slug.
	// Slugs are unique per (tenant_id, namespace_path); the namespace
	// argument disambiguates roles that share the same slug across
	// different namespace scopes.
	GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*Role, error)

	// UpdateRole persists changes to a role. The row is matched on both the
	// ID and r.TenantID, and tenant_id is never part of the write, so an
	// update can neither reach into another tenant nor move a row between
	// tenants. Returns ErrRoleNotFound when nothing matches.
	UpdateRole(ctx context.Context, r *Role) error

	// DeleteRole removes a role by ID within a tenant.
	DeleteRole(ctx context.Context, tenantID string, roleID id.RoleID) error

	// ListRoles returns roles matching the filter.
	ListRoles(ctx context.Context, filter *ListFilter) ([]*Role, error)

	// CountRoles returns the number of roles matching the filter.
	CountRoles(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRolePermissions returns the full Permission records granted to a
	// role, resolved via JOIN against warden_permissions. Returning the full
	// records avoids the engine's previous N+1 GetPermission loop in the
	// RBAC evaluator.
	ListRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error)

	// ListRolePermissionsForRoles resolves the grants of several roles in one
	// round trip, keyed by role ID. Roles that grant nothing, or that belong
	// to another tenant, are absent from the map.
	ListRolePermissionsForRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) (map[id.RoleID][]*permission.Permission, error)

	// AttachPermission links a permission to a role by natural key.
	// The (NamespacePath, Name) pair uniquely identifies a permission within
	// the role's tenant. Returns ErrRoleNotFound when the role is not in the
	// tenant.
	AttachPermission(ctx context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error

	// DetachPermission removes a permission grant from a role.
	DetachPermission(ctx context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error

	// SetRolePermissions replaces all permission grants for a role.
	SetRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID, refs []permission.Ref) error

	// ListChildRoles returns direct child roles of a parent within a tenant.
	// Children are inherently per-tenant since slugs are unique per tenant.
	ListChildRoles(ctx context.Context, tenantID, parentSlug string) ([]*Role, error)

	// DeleteRolesByTenant removes all roles for a tenant.
	DeleteRolesByTenant(ctx context.Context, tenantID string) error
}
