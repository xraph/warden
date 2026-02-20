package resourcetype

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for resource type definitions.
type Store interface {
	// CreateResourceType persists a new resource type.
	CreateResourceType(ctx context.Context, rt *ResourceType) error

	// GetResourceType retrieves a resource type by ID.
	GetResourceType(ctx context.Context, rtID id.ResourceTypeID) (*ResourceType, error)

	// GetResourceTypeByName retrieves a resource type by tenant and name.
	GetResourceTypeByName(ctx context.Context, tenantID, name string) (*ResourceType, error)

	// UpdateResourceType persists changes to a resource type.
	UpdateResourceType(ctx context.Context, rt *ResourceType) error

	// DeleteResourceType removes a resource type by ID.
	DeleteResourceType(ctx context.Context, rtID id.ResourceTypeID) error

	// ListResourceTypes returns resource types matching the filter.
	ListResourceTypes(ctx context.Context, filter *ListFilter) ([]*ResourceType, error)

	// CountResourceTypes returns the number of resource types matching the filter.
	CountResourceTypes(ctx context.Context, filter *ListFilter) (int64, error)

	// DeleteResourceTypesByTenant removes all resource types for a tenant.
	DeleteResourceTypesByTenant(ctx context.Context, tenantID string) error
}
