package warden

import (
	"context"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

func TestCheck_WithCallTenantID(t *testing.T) {
	// Context has tenant "t1", data lives in "t2".
	// WithCallTenantID("t2") should override and find the data.
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	setupRBACData(t, s, "t2", "user", "u1", "document", "read")

	// Without call option — uses context tenant "t1", should deny.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied when using context tenant t1")
	}

	// With call option — overrides to "t2", should allow.
	result, err = eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	}, WithCallTenantID("t2"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed with WithCallTenantID, got %s: %s", result.Decision, result.Reason)
	}
}

func TestCheck_CallOptionOverridesRequestTenantID(t *testing.T) {
	// CheckRequest.TenantID = "t2", CallOption = "t3".
	// Data lives in "t3". CallOption should win.
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	setupRBACData(t, s, "t3", "user", "u1", "document", "read")

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
		TenantID: "t2", // request-level override — should be overridden by call option
	}, WithCallTenantID("t3"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed: CallOption should override req.TenantID, got %s: %s", result.Decision, result.Reason)
	}
}

func TestEnforce_WithCallTenantID(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	setupRBACData(t, s, "t2", "user", "u1", "document", "read")

	// Without call option — denied.
	err := eng.Enforce(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err == nil {
		t.Fatal("expected error when using context tenant t1")
	}

	// With call option — allowed.
	err = eng.Enforce(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	}, WithCallTenantID("t2"))
	if err != nil {
		t.Fatalf("expected no error with WithCallTenantID, got %v", err)
	}
}

func TestCanI_WithCallTenantID(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	setupRBACData(t, s, "t2", "user", "u1", "document", "read")

	// Without call option — denied.
	allowed, err := eng.CanI(ctx, SubjectUser, "u1", "read", "document", "doc1")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("expected denied when using context tenant t1")
	}

	// With call option — allowed.
	allowed, err = eng.CanI(ctx, SubjectUser, "u1", "read", "document", "doc1", WithCallTenantID("t2"))
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected allowed with WithCallTenantID")
	}
}

func TestCheck_WithCallAppID(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	// Simply verify the call option doesn't cause errors.
	// AppID is used for scoping but doesn't affect check logic directly.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	}, WithCallAppID("app2"))
	if err != nil {
		t.Fatal(err)
	}
	// Default deny expected — no data.
	if result.Allowed {
		t.Fatal("expected denied")
	}
}

func TestCheck_NoCallOptions_BackwardsCompatible(t *testing.T) {
	// Verify existing behavior is unchanged when no call options are passed.
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	setupRBACData(t, s, "t1", "user", "u1", "document", "read")

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed, got %s: %s", result.Decision, result.Reason)
	}
}

// setupRBACData creates a role, permission, attachment, and assignment for testing.
func setupRBACData(t *testing.T, s *memory.Store, tenantID, subjectKind, subjectID, resource, action string) {
	t.Helper()
	ctx := context.Background()

	roleID := id.NewRoleID()
	permID := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: tenantID, Name: resource + "-" + action, Slug: resource + "-" + action})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: tenantID, Name: resource + ":" + action, Resource: resource, Action: action})
	_ = s.AttachPermission(ctx, roleID, permID)
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: tenantID,
		RoleID: roleID, SubjectKind: subjectKind, SubjectID: subjectID,
	})
}
