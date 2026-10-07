package role_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
	"github.com/xraph/warden/wardenerr"
)

const tenant = "t1"

// GrantingRoles reads every page, so a role past the first page of 200 is
// still named and the delete guard still refuses.
func TestCheckPermissionUngrantedReadsEveryPage(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	pm := &permission.Permission{TenantID: tenant, Name: "doc:read", Resource: "doc", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	var last *role.Role
	for i := 0; i < 450; i++ {
		last = &role.Role{TenantID: tenant, Name: fmt.Sprintf("R%03d", i), Slug: fmt.Sprintf("r%03d", i)}
		if err := s.CreateRole(ctx, last); err != nil {
			t.Fatalf("create role: %v", err)
		}
	}
	if err := role.CheckPermissionUngranted(ctx, s, tenant, pm); err != nil {
		t.Fatalf("nothing grants it yet: %v", err)
	}
	if err := s.AttachPermission(ctx, tenant, last.ID, permission.Ref{Name: "doc:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	err := role.CheckPermissionUngranted(ctx, s, tenant, pm)
	var granted *role.PermissionGrantedError
	if !errors.As(err, &granted) {
		t.Fatalf("err = %v, want a *PermissionGrantedError", err)
	}
	if want := "doc:read is still granted by r449. Detach it from those roles first."; err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
}

// A grant of the same name in another namespace is a different grant.
func TestGrantingRolesMatchesTheNamespace(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	root := &permission.Permission{TenantID: tenant, Name: "doc:read", Resource: "doc", Action: "read"}
	eng := &permission.Permission{TenantID: tenant, NamespacePath: "eng", Name: "doc:read", Resource: "doc", Action: "read"}
	for _, p := range []*permission.Permission{root, eng} {
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("create permission: %v", err)
		}
	}
	r := &role.Role{TenantID: tenant, Name: "Editor", Slug: "editor"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := s.AttachPermission(ctx, tenant, r.ID, permission.Ref{NamespacePath: "eng", Name: "doc:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if got, err := role.GrantingRoles(ctx, s, tenant, root); err != nil || len(got) != 0 {
		t.Errorf("root doc:read: got %v, %v; want no roles", got, err)
	}
	if got, err := role.GrantingRoles(ctx, s, tenant, eng); err != nil || len(got) != 1 || got[0].Slug != "editor" {
		t.Errorf("eng doc:read: got %v, %v; want editor", got, err)
	}
}

func TestHeldGrant(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	pm := &permission.Permission{TenantID: tenant, Name: "doc:read", Resource: "doc", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	r := &role.Role{TenantID: tenant, Name: "Editor", Slug: "editor"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := s.AttachPermission(ctx, tenant, r.ID, permission.Ref{Name: "doc:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if g, err := role.HeldGrant(ctx, s, tenant, r, permission.Ref{Name: "doc:read"}); err != nil || g.ID != pm.ID {
		t.Fatalf("held grant: got %v, %v", g, err)
	}
	for _, ref := range []permission.Ref{{Name: "doc:write"}, {NamespacePath: "eng", Name: "doc:read"}} {
		_, err := role.HeldGrant(ctx, s, tenant, r, ref)
		var notHeld *role.GrantNotHeldError
		if !errors.As(err, &notHeld) || !errors.Is(err, wardenerr.ErrNotFound) {
			t.Errorf("%+v: err = %v, want a *GrantNotHeldError wrapping ErrNotFound", ref, err)
			continue
		}
		if want := "Editor does not grant " + ref.Name; err.Error() != want {
			t.Errorf("%+v: message = %q, want %q", ref, err.Error(), want)
		}
	}
}

// failingGrants fails every read, which the checks must return as is
// rather than read as "nothing grants it" or "not held".
type failingGrants struct{ err error }

func (f failingGrants) ListRoles(context.Context, *role.ListFilter) ([]*role.Role, error) {
	return nil, f.err
}

func (f failingGrants) ListRolePermissionsForRoles(context.Context, string, []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	return nil, f.err
}

func (f failingGrants) ListRolePermissions(context.Context, string, id.RoleID) ([]*permission.Permission, error) {
	return nil, f.err
}

func TestGrantChecksReturnAStoreFailure(t *testing.T) {
	boom := errors.New("store down")
	s := failingGrants{err: boom}
	if err := role.CheckPermissionUngranted(context.Background(), s, tenant, &permission.Permission{Name: "doc:read"}); !errors.Is(err, boom) {
		t.Errorf("CheckPermissionUngranted: err = %v, want the store failure", err)
	}
	if _, err := role.HeldGrant(context.Background(), s, tenant, &role.Role{Name: "Editor"}, permission.Ref{Name: "doc:read"}); !errors.Is(err, boom) {
		t.Errorf("HeldGrant: err = %v, want the store failure", err)
	}
}
