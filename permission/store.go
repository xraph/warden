package permission

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for permissions.
//
// Every by-ID operation takes the tenant as a mandatory parameter and
// filters on it alongside the primary key. A call whose tenant does not own
// the row returns ErrPermissionNotFound and changes nothing.
type Store interface {
	// CreatePermission persists a new permission.
	CreatePermission(ctx context.Context, p *Permission) error

	// GetPermission retrieves a permission by ID within a tenant.
	GetPermission(ctx context.Context, tenantID string, permID id.PermissionID) (*Permission, error)

	// GetPermissionByName retrieves a permission by tenant, namespace, and name.
	// Names are unique per (tenant_id, namespace_path); the namespace argument
	// disambiguates permissions sharing a name across different namespaces.
	GetPermissionByName(ctx context.Context, tenantID, namespacePath, name string) (*Permission, error)

	// UpdatePermission persists changes to a permission. The row is matched
	// on both the ID and p.TenantID, and tenant_id is never written.
	UpdatePermission(ctx context.Context, p *Permission) error

	// DeletePermission removes a permission by ID within a tenant, along with
	// the role junction rows that grant it, matched on
	// (tenant_id, namespace_path, name).
	DeletePermission(ctx context.Context, tenantID string, permID id.PermissionID) error

	// ListPermissions returns permissions matching the filter.
	ListPermissions(ctx context.Context, filter *ListFilter) ([]*Permission, error)

	// CountPermissions returns the number of permissions matching the filter.
	CountPermissions(ctx context.Context, filter *ListFilter) (int64, error)

	// ListPermissionsByRole returns all permissions attached to a role
	// within a tenant.
	ListPermissionsByRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*Permission, error)

	// ListPermissionsBySubject returns all permissions granted to a subject
	// through their assigned roles.
	ListPermissionsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]*Permission, error)

	// DeletePermissionsByTenant removes all permissions for a tenant.
	DeletePermissionsByTenant(ctx context.Context, tenantID string) error
}
