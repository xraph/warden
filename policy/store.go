package policy

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for ABAC policies.
type Store interface {
	// CreatePolicy persists a new policy.
	CreatePolicy(ctx context.Context, p *Policy) error

	// GetPolicy retrieves a policy by ID.
	GetPolicy(ctx context.Context, polID id.PolicyID) (*Policy, error)

	// GetPolicyByName retrieves a policy by tenant and name.
	GetPolicyByName(ctx context.Context, tenantID, name string) (*Policy, error)

	// UpdatePolicy persists changes to a policy.
	UpdatePolicy(ctx context.Context, p *Policy) error

	// DeletePolicy removes a policy by ID.
	DeletePolicy(ctx context.Context, polID id.PolicyID) error

	// ListPolicies returns policies matching the filter.
	ListPolicies(ctx context.Context, filter *ListFilter) ([]*Policy, error)

	// CountPolicies returns the number of policies matching the filter.
	CountPolicies(ctx context.Context, filter *ListFilter) (int64, error)

	// ListActivePolicies returns all active policies for a tenant.
	ListActivePolicies(ctx context.Context, tenantID string) ([]*Policy, error)

	// SetPolicyVersion updates a policy's version number.
	SetPolicyVersion(ctx context.Context, polID id.PolicyID, version int) error

	// DeletePoliciesByTenant removes all policies for a tenant.
	DeletePoliciesByTenant(ctx context.Context, tenantID string) error
}
