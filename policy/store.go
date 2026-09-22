package policy

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for ABAC policies.
//
// Every by-ID operation takes the tenant as a mandatory parameter and
// filters on it alongside the primary key. A call whose tenant does not own
// the row returns ErrPolicyNotFound and changes nothing.
type Store interface {
	// CreatePolicy persists a new policy.
	CreatePolicy(ctx context.Context, p *Policy) error

	// GetPolicy retrieves a policy by ID within a tenant.
	GetPolicy(ctx context.Context, tenantID string, polID id.PolicyID) (*Policy, error)

	// GetPolicyByName retrieves a policy by tenant, namespace, and name.
	// Names are unique per (tenant_id, namespace_path).
	GetPolicyByName(ctx context.Context, tenantID, namespacePath, name string) (*Policy, error)

	// UpdatePolicy persists changes to a policy. The row is matched on both
	// the ID and p.TenantID, and tenant_id is never written.
	UpdatePolicy(ctx context.Context, p *Policy) error

	// DeletePolicy removes a policy by ID within a tenant.
	DeletePolicy(ctx context.Context, tenantID string, polID id.PolicyID) error

	// ListPolicies returns policies matching the filter.
	ListPolicies(ctx context.Context, filter *ListFilter) ([]*Policy, error)

	// CountPolicies returns the number of policies matching the filter.
	CountPolicies(ctx context.Context, filter *ListFilter) (int64, error)

	// ListActivePolicies returns all active policies for a tenant across the
	// given namespace paths. Pass nil or an empty slice to match any namespace
	// (legacy/unscoped behavior). Policies are merged across paths at the
	// engine layer; ordering is by priority within the union.
	ListActivePolicies(ctx context.Context, tenantID string, namespacePaths []string) ([]*Policy, error)

	// SetPolicyVersion updates a policy's version number within a tenant.
	SetPolicyVersion(ctx context.Context, tenantID string, polID id.PolicyID, version int) error

	// DeletePoliciesByTenant removes all policies for a tenant.
	DeletePoliciesByTenant(ctx context.Context, tenantID string) error
}
