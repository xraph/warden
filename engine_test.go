package warden

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

func newTestEngine(t *testing.T) (*Engine, *memory.Store) {
	t.Helper()
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	return eng, s
}

func TestNewEngine_RequiresStore(t *testing.T) {
	_, err := NewEngine()
	if err == nil {
		t.Fatal("expected error when store is nil")
	}
}

func TestRBACFlow(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Create role + permission.
	roleID := id.NewRoleID()
	permID := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "editor", Slug: "editor"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"})
	_ = s.AttachPermission(ctx, roleID, permID)

	// Assign role to user.
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID:          id.NewAssignmentID(),
		TenantID:    "t1",
		RoleID:      roleID,
		SubjectKind: "user",
		SubjectID:   "u1",
	})

	// Check: user u1 should be allowed to read documents.
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
	if result.Decision != DecisionAllow {
		t.Fatalf("expected decision allow, got %s", result.Decision)
	}

	// Check: user u1 should NOT be allowed to delete documents (no perm).
	result, err = eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied for delete")
	}
}

func TestRBACRoleInheritance(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Create parent role with permission.
	parentID := id.NewRoleID()
	childID := id.NewRoleID()
	permID := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: parentID, TenantID: "t1", Name: "viewer", Slug: "viewer"})
	_ = s.CreateRole(ctx, &role.Role{ID: childID, TenantID: "t1", Name: "editor", Slug: "editor", ParentID: &parentID})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"})
	_ = s.AttachPermission(ctx, parentID, permID)

	// Assign child role to user.
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: childID, SubjectKind: "user", SubjectID: "u1",
	})

	// User should inherit parent's permissions.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed via inheritance, got %s: %s", result.Decision, result.Reason)
	}
}

func TestReBAC_DirectRelation(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Create direct relation: user u1 is viewer of document doc1.
	_ = s.CreateRelation(ctx, &relation.Tuple{
		ID:          id.NewRelationID(),
		TenantID:    "t1",
		ObjectType:  "document",
		ObjectID:    "doc1",
		Relation:    "read",
		SubjectType: "user",
		SubjectID:   "u1",
	})

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed via direct relation, got %s: %s", result.Decision, result.Reason)
	}
}

func TestReBAC_TransitiveRelation(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// document:doc1#read -> folder:f1#read (subject set: read on folder grants read on doc)
	_ = s.CreateRelation(ctx, &relation.Tuple{
		ID: id.NewRelationID(), TenantID: "t1",
		ObjectType: "document", ObjectID: "doc1", Relation: "read",
		SubjectType: "folder", SubjectID: "f1", SubjectRelation: "read",
	})
	// folder:f1#read -> user:u1
	_ = s.CreateRelation(ctx, &relation.Tuple{
		ID: id.NewRelationID(), TenantID: "t1",
		ObjectType: "folder", ObjectID: "f1", Relation: "read",
		SubjectType: "user", SubjectID: "u1",
	})

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed via transitive relation, got %s: %s", result.Decision, result.Reason)
	}
}

func TestABACFlow(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Create allow policy for users with role=admin attribute.
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID:       id.NewPolicyID(),
		TenantID: "t1",
		Name:     "admin-allow",
		Effect:   policy.EffectAllow,
		IsActive: true,
		Subjects: []policy.SubjectMatch{{Kind: "user"}},
		Actions:  []string{"*"},
		Conditions: []policy.Condition{
			{Field: "subject.role", Operator: policy.OpEquals, Value: "admin"},
		},
	})

	// Check with matching attribute.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1", Attributes: map[string]any{"role": "admin"}},
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed for admin, got %s: %s", result.Decision, result.Reason)
	}

	// Check with non-matching attribute.
	result, err = eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u2", Attributes: map[string]any{"role": "viewer"}},
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied for non-admin")
	}
}

func TestABACDenyOverridesAllow(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Allow policy.
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "allow-all",
		Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"*"},
	})
	// Deny policy for specific IP range.
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "deny-internal",
		Effect: policy.EffectDeny, IsActive: true,
		Actions: []string{"*"},
		Conditions: []policy.Condition{
			{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: "10.0.0.0/8"},
		},
	})

	// Request from internal IP — should be denied.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
		Context:  map[string]any{"ip": "10.0.1.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied for internal IP")
	}
	if result.Decision != DecisionDenyExplicit {
		t.Fatalf("expected explicit deny, got %s", result.Decision)
	}

	// Request from external IP — should be allowed.
	result, err = eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
		Context:  map[string]any{"ip": "203.0.113.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed for external IP, got %s: %s", result.Decision, result.Reason)
	}
}

func TestEnforce(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "allow-all",
		Effect: policy.EffectAllow, IsActive: true, Actions: []string{"*"},
	})

	err := eng.Enforce(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatalf("expected no error for allowed check, got %v", err)
	}
}

func TestCanI(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "allow-all",
		Effect: policy.EffectAllow, IsActive: true, Actions: []string{"*"},
	})

	allowed, err := eng.CanI(ctx, SubjectUser, "u1", "read", "doc", "d1")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected allowed")
	}
}

func TestDefaultDeny(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	// No roles, no relations, no policies — should be default deny.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected default deny")
	}
}

func TestCheckEvalTime(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EvalTimeNs <= 0 {
		t.Fatal("expected positive eval time")
	}
}

func TestResourceScopedRole(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	roleID := id.NewRoleID()
	permID := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "doc-editor", Slug: "doc-editor"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "t1", Name: "document:write", Resource: "document", Action: "write"})
	_ = s.AttachPermission(ctx, roleID, permID)

	// Assign role scoped to a specific document.
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: roleID,
		SubjectKind: "user", SubjectID: "u1",
		ResourceType: "document", ResourceID: "doc1",
	})

	// Check on the scoped resource — should pass.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "write"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed on scoped resource, got %s: %s", result.Decision, result.Reason)
	}
}

func TestABACTimeCondition(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "time-limited",
		Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"*"},
		Conditions: []policy.Condition{
			{Field: "context.time", Operator: policy.OpTimeBefore, Value: future},
		},
	})

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
		Context:  map[string]any{"time": time.Now().Format(time.RFC3339)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed before time limit, got %s: %s", result.Decision, result.Reason)
	}
}

func TestCheckWithTenantOverride(t *testing.T) {
	// Context has tenant "t1", but CheckRequest overrides to "t2".
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Create role + permission in tenant "t2".
	roleID := id.NewRoleID()
	permID := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t2", Name: "admin", Slug: "admin"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "t2", Name: "document:read", Resource: "document", Action: "read"})
	_ = s.AttachPermission(ctx, roleID, permID)
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t2",
		RoleID: roleID, SubjectKind: "user", SubjectID: "u1",
	})

	// Without tenant override — context tenant "t1" is used, should be denied.
	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied when using context tenant t1 (no data in t1)")
	}

	// With tenant override — should use "t2" and find the role/permission.
	result, err = eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
		TenantID: "t2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed with tenant override t2, got %s: %s", result.Decision, result.Reason)
	}
}

func TestCheck_MissingResourceType(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	_, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "", ID: "doc1"},
	})
	if err == nil {
		t.Fatal("expected error for missing resource type")
	}
	if !strings.Contains(err.Error(), "resource type is required") {
		t.Fatalf("expected error about resource type, got: %v", err)
	}
}

func TestCheck_MissingSubjectID(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	_, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: ""},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err == nil {
		t.Fatal("expected error for missing subject ID")
	}
	if !strings.Contains(err.Error(), "subject ID is required") {
		t.Fatalf("expected error about subject ID, got: %v", err)
	}
}

func TestCheck_MissingAction(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	_, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: ""},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err == nil {
		t.Fatal("expected error for missing action")
	}
	if !strings.Contains(err.Error(), "action name is required") {
		t.Fatalf("expected error about action, got: %v", err)
	}
}

func TestCheck_DenyReasonIncludesContext(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Create a role but no permission — should get "no role grants permission" with details.
	roleID := id.NewRoleID()
	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "viewer", Slug: "viewer"})
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: roleID, SubjectKind: "user", SubjectID: "u1",
	})

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied")
	}
	// Reason should include the permission name and subject.
	if !strings.Contains(result.Reason, "document:delete") {
		t.Fatalf("expected reason to include permission name, got: %s", result.Reason)
	}
	if !strings.Contains(result.Reason, "user:u1") {
		t.Fatalf("expected reason to include subject, got: %s", result.Reason)
	}
}

func TestCheck_DenyNoRolesReasonIncludesSubject(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, _ := newTestEngine(t)

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("expected denied")
	}
	// With all models enabled, the merged result should contain informative context.
	if result.Reason == "" {
		t.Fatal("expected non-empty reason")
	}
}
