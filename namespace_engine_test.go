package warden

import (
	"context"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
)

// seedRBACAtNamespace creates a role + permission and assigns it to a subject
// at the given namespace. Returns the role ID for later use.
func seedRBACAtNamespace(t *testing.T, s seeder, tenantID, namespacePath, slug, permName, subjectKind, subjectID string) id.RoleID {
	t.Helper()
	ctx := context.Background()
	roleID := id.NewRoleID()
	permID := id.NewPermissionID()

	if err := s.CreateRole(ctx, &role.Role{
		ID: roleID, TenantID: tenantID, NamespacePath: namespacePath, Name: slug, Slug: slug,
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	parts := splitPermName(permName)
	if err := s.CreatePermission(ctx, &permission.Permission{
		ID: permID, TenantID: tenantID, NamespacePath: namespacePath,
		Name: permName, Resource: parts[0], Action: parts[1],
	}); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	if err := s.AttachPermission(ctx, roleID, permID); err != nil {
		t.Fatalf("AttachPermission: %v", err)
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		ID:            id.NewAssignmentID(),
		TenantID:      tenantID,
		NamespacePath: namespacePath,
		RoleID:        roleID,
		SubjectKind:   subjectKind,
		SubjectID:     subjectID,
	}); err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}
	return roleID
}

func splitPermName(name string) [2]string {
	for i, c := range name {
		if c == ':' {
			return [2]string{name[:i], name[i+1:]}
		}
	}
	return [2]string{name, ""}
}

type seeder interface {
	CreateRole(ctx context.Context, r *role.Role) error
	CreatePermission(ctx context.Context, p *permission.Permission) error
	AttachPermission(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error
	CreateAssignment(ctx context.Context, a *assignment.Assignment) error
}

// TestNamespace_LocalLookup verifies that a role assigned at namespace N is
// found when checking at namespace N (the simplest case).
func TestNamespace_LocalLookup(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	ctx = WithNamespace(ctx, "engineering")
	eng, s := newTestEngine(t)

	seedRBACAtNamespace(t, s, "t1", "engineering", "viewer", "doc:read", "user", "u1")

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allow at local namespace, got %s: %s", result.Decision, result.Reason)
	}
}

// TestNamespace_AncestorFallback verifies that a role assigned at an ancestor
// namespace is visible to a Check at a descendant namespace (cascading scope).
func TestNamespace_AncestorFallback(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Role/perm/assignment all live at "engineering" (the ancestor).
	seedRBACAtNamespace(t, s, "t1", "engineering", "eng-viewer", "doc:read", "user", "u1")

	// Check happens at "engineering/platform/sre" (deepest descendant).
	deep := WithNamespace(ctx, "engineering/platform/sre")
	result, err := eng.Check(deep, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allow via ancestor inheritance, got %s: %s", result.Decision, result.Reason)
	}
}

// TestNamespace_SiblingIsolation verifies that a role assigned at one
// namespace branch is NOT visible from a sibling branch (no horizontal
// leakage).
func TestNamespace_SiblingIsolation(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// User u1 only has the role at "engineering".
	seedRBACAtNamespace(t, s, "t1", "engineering", "eng-viewer", "doc:read", "user", "u1")

	// Check at the sibling "billing" — should be denied.
	billingCtx := WithNamespace(ctx, "billing")
	result, err := eng.Check(billingCtx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatalf("expected DENY in sibling namespace, got %s: %s", result.Decision, result.Reason)
	}
}

// TestNamespace_AncestorDoesNotInheritFromDescendant verifies that a role
// assigned at a child namespace is NOT visible when checking at the parent
// (inheritance is ancestor → descendant only, not the other way).
func TestNamespace_AncestorDoesNotInheritFromDescendant(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// User u1 has the role only at the deeper namespace.
	seedRBACAtNamespace(t, s, "t1", "engineering/platform", "platform-only", "doc:read", "user", "u1")

	// Check at the parent namespace — should be denied.
	engCtx := WithNamespace(ctx, "engineering")
	result, err := eng.Check(engCtx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatalf("expected DENY at ancestor, got %s: %s", result.Decision, result.Reason)
	}
}

// TestNamespace_CrossTenantIsolation verifies the hard tenant boundary holds
// even with namespaces. A role at the same namespace path but a different
// tenant must not match.
func TestNamespace_CrossTenantIsolation(t *testing.T) {
	eng, s := newTestEngine(t)

	// Tenant t1 has the role.
	seedRBACAtNamespace(t, s, "t1", "engineering", "viewer", "doc:read", "user", "u1")

	// Check as tenant t2 at the same namespace — should be denied.
	t2Ctx := WithTenant(context.Background(), "app1", "t2")
	t2Ctx = WithNamespace(t2Ctx, "engineering")
	result, err := eng.Check(t2Ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatalf("expected DENY across tenants, got %s: %s", result.Decision, result.Reason)
	}
}

// TestNamespace_RootRolesVisibleEverywhere verifies that a role assigned at
// the tenant root (empty namespace path) is visible from every descendant.
func TestNamespace_RootRolesVisibleEverywhere(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	eng, s := newTestEngine(t)

	// Role at tenant root.
	seedRBACAtNamespace(t, s, "t1", "", "super-admin", "doc:read", "user", "u1")

	// Check at a deeply nested namespace.
	deep := WithNamespace(ctx, "engineering/platform/sre")
	result, err := eng.Check(deep, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allow from root, got %s: %s", result.Decision, result.Reason)
	}
}

// TestNamespace_CallOptionOverride verifies WithCallNamespacePath overrides
// context-derived namespace for a single call.
func TestNamespace_CallOptionOverride(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	ctx = WithNamespace(ctx, "billing") // context says billing
	eng, s := newTestEngine(t)

	seedRBACAtNamespace(t, s, "t1", "engineering", "viewer", "doc:read", "user", "u1")

	// Without override: should be denied (context = billing).
	denied, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Allowed {
		t.Fatalf("baseline: expected DENY in billing, got %s", denied.Decision)
	}

	// With override: switch to engineering.
	allowed, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}, WithCallNamespacePath("engineering"))
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatalf("expected allow with override, got %s: %s", allowed.Decision, allowed.Reason)
	}
}

// TestNamespace_RequestNamespaceOverridesContext verifies CheckRequest.NamespacePath
// overrides the context-derived namespace.
func TestNamespace_RequestNamespaceOverridesContext(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	ctx = WithNamespace(ctx, "billing")
	eng, s := newTestEngine(t)

	seedRBACAtNamespace(t, s, "t1", "engineering", "viewer", "doc:read", "user", "u1")

	result, err := eng.Check(ctx, &CheckRequest{
		Subject:       Subject{Kind: SubjectUser, ID: "u1"},
		Action:        Action{Name: "read"},
		Resource:      Resource{Type: "doc", ID: "d1"},
		NamespacePath: "engineering",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allow with request override, got %s: %s", result.Decision, result.Reason)
	}
}
