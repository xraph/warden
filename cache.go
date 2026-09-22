package warden

import "context"

// Cache provides caching for authorization check results.
//
// Get and Set take the resolved tenant ID and namespace path explicitly
// (rather than trusting CheckRequest.NamespacePath, which callers may
// leave unset when they rely on context-derived scope) so the cache key
// always reflects the namespace the check actually ran against.
type Cache interface {
	// Get returns a cached check result, if available.
	Get(ctx context.Context, tenantID, namespacePath string, req *CheckRequest) (*CheckResult, bool)

	// Set stores a check result in the cache.
	Set(ctx context.Context, tenantID, namespacePath string, req *CheckRequest, result *CheckResult)

	// InvalidateTenant removes all cached results for a tenant.
	InvalidateTenant(ctx context.Context, tenantID string)

	// InvalidateSubject removes all cached results for a specific subject.
	InvalidateSubject(ctx context.Context, tenantID string, subjectKind SubjectKind, subjectID string)

	// Clear removes every cached entry across every tenant. Used by
	// maintenance and by invalidation paths that cannot be scoped to a
	// single tenant (e.g. a delete hook that only carries a bare ID).
	Clear(ctx context.Context)
}
