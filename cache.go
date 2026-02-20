package warden

import "context"

// Cache provides caching for authorization check results.
type Cache interface {
	// Get returns a cached check result, if available.
	Get(ctx context.Context, tenantID string, req *CheckRequest) (*CheckResult, bool)

	// Set stores a check result in the cache.
	Set(ctx context.Context, tenantID string, req *CheckRequest, result *CheckResult)

	// InvalidateTenant removes all cached results for a tenant.
	InvalidateTenant(ctx context.Context, tenantID string)

	// InvalidateSubject removes all cached results for a specific subject.
	InvalidateSubject(ctx context.Context, tenantID string, subjectKind SubjectKind, subjectID string)
}
