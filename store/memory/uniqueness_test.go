package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
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
