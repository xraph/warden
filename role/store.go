package role

import (
	"context"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
)

// Store defines persistence operations for roles.
type Store interface {
	// CreateRole persists a new role.
	CreateRole(ctx context.Context, r *Role) error

	// GetRole retrieves a role by ID.
	GetRole(ctx context.Context, roleID id.RoleID) (*Role, error)

	// GetRoleBySlug retrieves a role by tenant, namespace, and slug.
	// Slugs are unique per (tenant_id, namespace_path); the namespace
	// argument disambiguates roles that share the same slug across
	// different namespace scopes.
	GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*Role, error)

	// UpdateRole persists changes to a role.
	UpdateRole(ctx context.Context, r *Role) error

	// DeleteRole removes a role by ID.
	DeleteRole(ctx context.Context, roleID id.RoleID) error

	// ListRoles returns roles matching the filter.
	ListRoles(ctx context.Context, filter *ListFilter) ([]*Role, error)

	// CountRoles returns the number of roles matching the filter.
	CountRoles(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRolePermissions returns the full Permission records granted to a
	// role, resolved via JOIN against warden_permissions. Returning the full
	// records avoids the engine's previous N+1 GetPermission loop in the
	// RBAC evaluator.
	ListRolePermissions(ctx context.Context, roleID id.RoleID) ([]*permission.Permission, error)

	// AttachPermission links a permission to a role by natural key.
	// The (NamespacePath, Name) pair uniquely identifies a permission within
	// the role's tenant.
	AttachPermission(ctx context.Context, roleID id.RoleID, ref permission.Ref) error

	// DetachPermission removes a permission grant from a role.
	DetachPermission(ctx context.Context, roleID id.RoleID, ref permission.Ref) error

	// SetRolePermissions replaces all permission grants for a role.
	SetRolePermissions(ctx context.Context, roleID id.RoleID, refs []permission.Ref) error

	// ListChildRoles returns direct child roles of a parent within a tenant.
	// Children are inherently per-tenant since slugs are unique per tenant.
	ListChildRoles(ctx context.Context, tenantID, parentSlug string) ([]*Role, error)

	// DeleteRolesByTenant removes all roles for a tenant.
	DeleteRolesByTenant(ctx context.Context, tenantID string) error
}
