package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
)

// RunJunctionIntegrityContract asserts that the role/permission junction
// can't reference a permission that doesn't exist, and that deleting a
// permission fully scrubs the grants that pointed at it, so recreating a
// permission with the same natural key never silently hands its grants
// back to roles that lost them.
func RunJunctionIntegrityContract(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("AttachUnknownPermission_Rejected", func(t *testing.T) { runAttachUnknownPermission(t, mk) })
	t.Run("DeleteThenRecreatePermission_GrantNotRestored", func(t *testing.T) { runDeleteRecreatePermission(t, mk) })
}

func runAttachUnknownPermission(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	r := seedRole(t, s, "t1", "", "ji-role")
	ref := permission.Ref{NamespacePath: "", Name: "does-not-exist"}

	err := s.AttachPermission(ctx, "t1", r, ref)
	if !errors.Is(err, warden.ErrPermissionNotFound) {
		t.Fatalf("AttachPermission of an unknown permission: want ErrPermissionNotFound, got %v", err)
	}

	perms, lerr := s.ListRolePermissions(ctx, "t1", r)
	if lerr != nil {
		t.Fatalf("ListRolePermissions: %v", lerr)
	}
	if len(perms) != 0 {
		t.Errorf("rejected attach still recorded a grant: got %d", len(perms))
	}
}

func runDeleteRecreatePermission(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	r := seedRole(t, s, "t1", "", "ji-recreate-role")
	p := tiPermission(t, s, "t1", "ji-recreate-perm")
	ref := permission.Ref{NamespacePath: p.NamespacePath, Name: p.Name}

	if err := s.AttachPermission(ctx, "t1", r, ref); err != nil {
		t.Fatalf("AttachPermission: %v", err)
	}
	perms, err := s.ListRolePermissions(ctx, "t1", r)
	if err != nil || len(perms) != 1 {
		t.Fatalf("ListRolePermissions after attach: want 1, got %d (err %v)", len(perms), err)
	}

	if err := s.DeletePermission(ctx, "t1", p.ID); err != nil {
		t.Fatalf("DeletePermission: %v", err)
	}
	perms, err = s.ListRolePermissions(ctx, "t1", r)
	if err != nil {
		t.Fatalf("ListRolePermissions after delete: %v", err)
	}
	if len(perms) != 0 {
		t.Errorf("grant survived permission delete: want 0, got %d", len(perms))
	}

	// Recreate a permission with the exact same natural key. The role must
	// not regain the grant just because the name matches again: the
	// original junction row is gone, and nothing re-attaches it.
	recreated := &permission.Permission{
		ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: p.NamespacePath,
		Name: p.Name, Resource: p.Resource, Action: p.Action,
	}
	if err := s.CreatePermission(ctx, recreated); err != nil {
		t.Fatalf("recreate permission: %v", err)
	}
	perms, err = s.ListRolePermissions(ctx, "t1", r)
	if err != nil {
		t.Fatalf("ListRolePermissions after recreate: %v", err)
	}
	if len(perms) != 0 {
		t.Errorf("role regained a grant after the permission was recreated: want 0, got %d", len(perms))
	}
}
