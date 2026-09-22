package resourcetype

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for resource type definitions.
//
// Every by-ID operation takes the tenant as a mandatory parameter and
// filters on it alongside the primary key. A call whose tenant does not own
// the row returns ErrResourceTypeNotFound and changes nothing.
type Store interface {
	// CreateResourceType persists a new resource type.
	CreateResourceType(ctx context.Context, rt *ResourceType) error

	// GetResourceType retrieves a resource type by ID within a tenant.
	GetResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) (*ResourceType, error)

	// GetResourceTypeByName retrieves a resource type by tenant, namespace, and name.
	// Names are unique per (tenant_id, namespace_path).
	GetResourceTypeByName(ctx context.Context, tenantID, namespacePath, name string) (*ResourceType, error)

	// UpdateResourceType persists changes to a resource type. The row is
	// matched on both the ID and rt.TenantID, and tenant_id is never written.
	UpdateResourceType(ctx context.Context, rt *ResourceType) error

	// DeleteResourceType removes a resource type by ID within a tenant.
	DeleteResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) error

	// ListResourceTypes returns resource types matching the filter.
	ListResourceTypes(ctx context.Context, filter *ListFilter) ([]*ResourceType, error)

	// CountResourceTypes returns the number of resource types matching the filter.
	CountResourceTypes(ctx context.Context, filter *ListFilter) (int64, error)

	// DeleteResourceTypesByTenant removes all resource types for a tenant.
	DeleteResourceTypesByTenant(ctx context.Context, tenantID string) error
}
