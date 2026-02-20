package role

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for roles.
type Store interface {
	// CreateRole persists a new role.
	CreateRole(ctx context.Context, r *Role) error

	// GetRole retrieves a role by ID.
	GetRole(ctx context.Context, roleID id.RoleID) (*Role, error)

	// GetRoleBySlug retrieves a role by tenant and slug.
	GetRoleBySlug(ctx context.Context, tenantID, slug string) (*Role, error)

	// UpdateRole persists changes to a role.
	UpdateRole(ctx context.Context, r *Role) error

	// DeleteRole removes a role by ID.
	DeleteRole(ctx context.Context, roleID id.RoleID) error

	// ListRoles returns roles matching the filter.
	ListRoles(ctx context.Context, filter *ListFilter) ([]*Role, error)

	// CountRoles returns the number of roles matching the filter.
	CountRoles(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRolePermissions returns permission IDs attached to a role.
	ListRolePermissions(ctx context.Context, roleID id.RoleID) ([]id.PermissionID, error)

	// AttachPermission links a permission to a role.
	AttachPermission(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error

	// DetachPermission removes a permission from a role.
	DetachPermission(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error

	// SetRolePermissions replaces all permissions for a role.
	SetRolePermissions(ctx context.Context, roleID id.RoleID, permIDs []id.PermissionID) error

	// ListChildRoles returns direct child roles of a parent.
	ListChildRoles(ctx context.Context, parentID id.RoleID) ([]*Role, error)

	// DeleteRolesByTenant removes all roles for a tenant.
	DeleteRolesByTenant(ctx context.Context, tenantID string) error
}
