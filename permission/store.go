package permission

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for permissions.
type Store interface {
	// CreatePermission persists a new permission.
	CreatePermission(ctx context.Context, p *Permission) error

	// GetPermission retrieves a permission by ID.
	GetPermission(ctx context.Context, permID id.PermissionID) (*Permission, error)

	// GetPermissionByName retrieves a permission by tenant and name.
	GetPermissionByName(ctx context.Context, tenantID, name string) (*Permission, error)

	// UpdatePermission persists changes to a permission.
	UpdatePermission(ctx context.Context, p *Permission) error

	// DeletePermission removes a permission by ID.
	DeletePermission(ctx context.Context, permID id.PermissionID) error

	// ListPermissions returns permissions matching the filter.
	ListPermissions(ctx context.Context, filter *ListFilter) ([]*Permission, error)

	// CountPermissions returns the number of permissions matching the filter.
	CountPermissions(ctx context.Context, filter *ListFilter) (int64, error)

	// ListPermissionsByRole returns all permissions attached to a role.
	ListPermissionsByRole(ctx context.Context, roleID id.RoleID) ([]*Permission, error)

	// ListPermissionsBySubject returns all permissions granted to a subject
	// through their assigned roles.
	ListPermissionsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]*Permission, error)

	// DeletePermissionsByTenant removes all permissions for a tenant.
	DeletePermissionsByTenant(ctx context.Context, tenantID string) error
}
