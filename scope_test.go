package warden

import (
	"context"
	"testing"

	"github.com/xraph/forge"
)

func TestScopeFromContext_WithTenantOverridesForgeScope(t *testing.T) {
	ctx := context.Background()

	// Simulate auth middleware: sets forge scope with empty OrgID.
	ctx = forge.WithScope(ctx, forge.NewAppScope("app_123"))

	// Simulate ensureWardenScope: sets explicit tenant to appID.
	ctx = WithTenant(ctx, "app_123", "app_123")

	scope := scopeFromContext(ctx)

	if scope.appID != "app_123" {
		t.Fatalf("expected appID %q, got %q", "app_123", scope.appID)
	}
	if scope.tenantID != "app_123" {
		t.Fatalf("expected tenantID %q, got %q", "app_123", scope.tenantID)
	}
}

func TestScopeFromContext_ForgeScopeWithOrg(t *testing.T) {
	ctx := context.Background()

	// Org-scoped session: OrgID is present.
	ctx = forge.WithScope(ctx, forge.NewOrgScope("app_123", "org_456"))

	scope := scopeFromContext(ctx)

	if scope.appID != "app_123" {
		t.Fatalf("expected appID %q, got %q", "app_123", scope.appID)
	}
	if scope.tenantID != "org_456" {
		t.Fatalf("expected tenantID %q, got %q", "org_456", scope.tenantID)
	}
}

func TestScopeFromContext_ForgeScopeWithOrgAndWithTenantOverride(t *testing.T) {
	ctx := context.Background()

	// Org-scoped session with forge scope.
	ctx = forge.WithScope(ctx, forge.NewOrgScope("app_123", "org_456"))

	// Explicit override to use a different tenant.
	ctx = WithTenant(ctx, "app_123", "org_789")

	scope := scopeFromContext(ctx)

	// WithTenant should take priority.
	if scope.tenantID != "org_789" {
		t.Fatalf("expected tenantID %q from WithTenant override, got %q", "org_789", scope.tenantID)
	}
}

func TestScopeFromContext_StandaloneMode(t *testing.T) {
	ctx := context.Background()

	// No forge scope, just WithTenant (standalone mode).
	ctx = WithTenant(ctx, "app_standalone", "tenant_standalone")

	scope := scopeFromContext(ctx)

	if scope.appID != "app_standalone" {
		t.Fatalf("expected appID %q, got %q", "app_standalone", scope.appID)
	}
	if scope.tenantID != "tenant_standalone" {
		t.Fatalf("expected tenantID %q, got %q", "tenant_standalone", scope.tenantID)
	}
}

func TestScopeFromContext_EmptyContext(t *testing.T) {
	ctx := context.Background()

	scope := scopeFromContext(ctx)

	if scope.appID != "" {
		t.Fatalf("expected empty appID, got %q", scope.appID)
	}
	if scope.tenantID != "" {
		t.Fatalf("expected empty tenantID, got %q", scope.tenantID)
	}
}
