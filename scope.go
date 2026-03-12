package warden

import (
	"context"

	"github.com/xraph/forge"
)

type tenantScope struct {
	appID    string
	tenantID string
}

// scopeFromContext extracts tenant scope from context. Explicit WithTenant
// values take priority over forge.Scope so that callers (e.g.
// ensureWardenScope) can override the tenant derived from forge scope when
// OrgID is empty (app-scoped sessions where roles are stored under appID).
func scopeFromContext(ctx context.Context) tenantScope {
	// 1. Check for explicit WithTenant values first — these take priority.
	if tid := tenantIDFromContext(ctx); tid != "" {
		return tenantScope{
			appID:    appIDFromContext(ctx),
			tenantID: tid,
		}
	}

	// 2. Fall back to forge.Scope.
	if s, ok := forge.ScopeFrom(ctx); ok {
		return tenantScope{
			appID:    s.AppID(),
			tenantID: s.OrgID(),
		}
	}

	// 3. Standalone mode with no tenant set.
	return tenantScope{
		appID:    appIDFromContext(ctx),
		tenantID: tenantIDFromContext(ctx),
	}
}
