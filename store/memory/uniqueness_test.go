package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

func TestCreateRole_DuplicateInSameScope_Rejected(t *testing.T) {
	ctx := context.Background()
	s := New()

	r1 := &role.Role{
		ID: id.NewRoleID(), TenantID: "t1", NamespacePath: "/app",
		Name: "Viewer", Slug: "viewer",
	}
	if err := s.CreateRole(ctx, r1); err != nil {
		t.Fatalf("first create unexpected error: %v", err)
	}

	r2 := &role.Role{
		ID: id.NewRoleID(), TenantID: "t1", NamespacePath: "/app",
		Name: "Viewer 2", Slug: "viewer", // SAME slug, same scope
	}
	err := s.CreateRole(ctx, r2)
	if err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
	if !errors.Is(err, warden.ErrDuplicateRole) {
		t.Fatalf("expected ErrDuplicateRole, got %v", err)
	}
	if !errors.Is(err, warden.ErrAlreadyExists) {
		t.Fatalf("expected error to wrap ErrAlreadyExists, got %v", err)
	}
}

func TestCreateRole_DuplicateSlugInDifferentNamespace_Allowed(t *testing.T) {
	ctx := context.Background()
	s := New()

	for _, ns := range []string{"/app/v1", "/app/v2"} {
		err := s.CreateRole(ctx, &role.Role{
			ID: id.NewRoleID(), TenantID: "t1", NamespacePath: ns,
			Name: "Viewer", Slug: "viewer",
		})
		if err != nil {
			t.Fatalf("create in ns %q: unexpected error: %v", ns, err)
		}
	}
}

func TestCreateRole_DuplicateSlugInDifferentTenant_Allowed(t *testing.T) {
	ctx := context.Background()
	s := New()

	for _, tenant := range []string{"t1", "t2"} {
		err := s.CreateRole(ctx, &role.Role{
			ID: id.NewRoleID(), TenantID: tenant, NamespacePath: "/app",
			Name: "Viewer", Slug: "viewer",
		})
		if err != nil {
			t.Fatalf("create in tenant %q: unexpected error: %v", tenant, err)
		}
	}
}

func TestCreatePermission_DuplicateInSameScope_Rejected(t *testing.T) {
	ctx := context.Background()
	s := New()
	mk := func() *permission.Permission {
		return &permission.Permission{
			ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: "/app",
			Name: "doc:read", Resource: "doc", Action: "read",
		}
	}
	if err := s.CreatePermission(ctx, mk()); err != nil {
		t.Fatal(err)
	}
	err := s.CreatePermission(ctx, mk())
	if !errors.Is(err, warden.ErrDuplicatePermission) {
		t.Fatalf("expected ErrDuplicatePermission, got %v", err)
	}
	if !errors.Is(err, warden.ErrAlreadyExists) {
		t.Fatalf("expected to wrap ErrAlreadyExists, got %v", err)
	}
}

func TestCreatePermission_DuplicateNameInDifferentNamespace_Allowed(t *testing.T) {
	ctx := context.Background()
	s := New()
	for _, ns := range []string{"/app/v1", "/app/v2"} {
		err := s.CreatePermission(ctx, &permission.Permission{
			ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: ns,
			Name: "doc:read", Resource: "doc", Action: "read",
		})
		if err != nil {
			t.Fatalf("create in ns %q: unexpected error: %v", ns, err)
		}
	}
}

func TestCreatePolicy_DuplicateInSameScope_Rejected(t *testing.T) {
	ctx := context.Background()
	s := New()
	mk := func() *policy.Policy {
		return &policy.Policy{
			ID: id.NewPolicyID(), TenantID: "t1", NamespacePath: "/app",
			Name: "no-after-hours", Effect: policy.EffectDeny,
		}
	}
	if err := s.CreatePolicy(ctx, mk()); err != nil {
		t.Fatal(err)
	}
	err := s.CreatePolicy(ctx, mk())
	if !errors.Is(err, warden.ErrDuplicatePolicy) {
		t.Fatalf("expected ErrDuplicatePolicy, got %v", err)
	}
}

func TestCreateResourceType_DuplicateInSameScope_Rejected(t *testing.T) {
	ctx := context.Background()
	s := New()
	mk := func() *resourcetype.ResourceType {
		return &resourcetype.ResourceType{
			ID: id.NewResourceTypeID(), TenantID: "t1", NamespacePath: "/app",
			Name: "doc",
		}
	}
	if err := s.CreateResourceType(ctx, mk()); err != nil {
		t.Fatal(err)
	}
	err := s.CreateResourceType(ctx, mk())
	if !errors.Is(err, warden.ErrDuplicateResourceType) {
		t.Fatalf("expected ErrDuplicateResourceType, got %v", err)
	}
}

func TestCreateAssignment_DuplicateInSameScope_Rejected(t *testing.T) {
	ctx := context.Background()
	s := New()
	roleID := id.NewRoleID()
	mk := func() *assignment.Assignment {
		return &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: "/app",
			RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
			ResourceType: "", ResourceID: "",
		}
	}
	if err := s.CreateAssignment(ctx, mk()); err != nil {
		t.Fatal(err)
	}
	err := s.CreateAssignment(ctx, mk())
	if !errors.Is(err, warden.ErrDuplicateAssignment) {
		t.Fatalf("expected ErrDuplicateAssignment, got %v", err)
	}
}

func TestCreateAssignment_SameRoleSubjectInDifferentScopedResource_Allowed(t *testing.T) {
	ctx := context.Background()
	s := New()
	roleID := id.NewRoleID()
	for _, rid := range []string{"doc1", "doc2"} {
		err := s.CreateAssignment(ctx, &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: "/app",
			RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
			ResourceType: "doc", ResourceID: rid,
		})
		if err != nil {
			t.Fatalf("create scoped to %q: %v", rid, err)
		}
	}
}
