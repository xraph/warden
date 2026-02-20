package warden

import (
	"context"

	"github.com/xraph/forge"
)

type tenantScope struct {
	appID    string
	tenantID string
}

// scopeFromContext extracts tenant scope from forge.Scope or standalone context.
// Falls back to explicit tenant if Forge scope is not set (standalone mode).
func scopeFromContext(ctx context.Context) tenantScope {
	s, ok := forge.ScopeFrom(ctx)
	if ok {
		return tenantScope{
			appID:    s.AppID(),
			tenantID: s.OrgID(),
		}
	}
	return tenantScope{
		appID:    appIDFromContext(ctx),
		tenantID: tenantIDFromContext(ctx),
	}
}
