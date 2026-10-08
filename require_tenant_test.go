package warden

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden/store/memory"
)

// TestCheck_RequireTenantDefaultsToErrorWhenTenantMissing verifies M3:
// with RequireTenant at its default (true), Check returns ErrTenantRequired
// when the resolved scope has no tenant: no WithTenant in context, no
// CheckRequest.TenantID, no CallOption override.
func TestCheck_RequireTenantDefaultsToErrorWhenTenantMissing(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}

	_, err = eng.Check(context.Background(), &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("expected ErrTenantRequired, got %v", err)
	}
}

// TestCheck_RequireTenantFalseAllowsEmptyTenant verifies the escape hatch:
// setting Config.RequireTenant to false restores the pre-M3 behavior for
// standalone/single-tenant deployments that never call WithTenant.
func TestCheck_RequireTenantFalseAllowsEmptyTenant(t *testing.T) {
	s := memory.New()
	f := false
	cfg := DefaultConfig()
	cfg.RequireTenant = &f
	eng, err := NewEngine(WithStore(s), WithConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}

	_, err = eng.Check(context.Background(), &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatalf("expected no error with RequireTenant=false, got %v", err)
	}
}

// TestCheck_RequireTenantSatisfiedByRequestTenantID verifies a tenant
// supplied via CheckRequest.TenantID (rather than context) satisfies
// RequireTenant.
func TestCheck_RequireTenantSatisfiedByRequestTenantID(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}

	_, err = eng.Check(context.Background(), &CheckRequest{
		TenantID: "t1",
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatalf("expected no error when TenantID is set on the request, got %v", err)
	}
}

// TestCheck_RequireTenantSatisfiedByCallOption verifies a tenant supplied
// via WithCallTenantID satisfies RequireTenant.
func TestCheck_RequireTenantSatisfiedByCallOption(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}

	_, err = eng.Check(context.Background(), &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}, WithCallTenantID("t1"))
	if err != nil {
		t.Fatalf("expected no error when tenant is set via CallOption, got %v", err)
	}
}
