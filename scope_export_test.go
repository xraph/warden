package warden

import (
	"context"
	"testing"

	"github.com/xraph/forge"
)

func TestScopeFromContext_Exported_WithTenant(t *testing.T) {
	ctx := WithTenant(context.Background(), "app_1", "tenant_1")

	appID, tenantID := ScopeFromContext(ctx)
	if appID != "app_1" {
		t.Fatalf("expected appID %q, got %q", "app_1", appID)
	}
	if tenantID != "tenant_1" {
		t.Fatalf("expected tenantID %q, got %q", "tenant_1", tenantID)
	}
}

func TestScopeFromContext_Exported_ForgeScope(t *testing.T) {
	ctx := forge.WithScope(context.Background(), forge.NewOrgScope("app_2", "org_2"))

	appID, tenantID := ScopeFromContext(ctx)
	if appID != "app_2" {
		t.Fatalf("expected appID %q, got %q", "app_2", appID)
	}
	if tenantID != "org_2" {
		t.Fatalf("expected tenantID %q, got %q", "org_2", tenantID)
	}
}

func TestScopeFromContext_Exported_Empty(t *testing.T) {
	ctx := context.Background()

	appID, tenantID := ScopeFromContext(ctx)
	if appID != "" {
		t.Fatalf("expected empty appID, got %q", appID)
	}
	if tenantID != "" {
		t.Fatalf("expected empty tenantID, got %q", tenantID)
	}
}
