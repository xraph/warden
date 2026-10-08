package contract

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func seedPermission(t *testing.T, s *memory.Store, name, resource, action string) *permission.Permission {
	t.Helper()
	pm := &permission.Permission{
		TenantID: "t1",
		Name:     name, Resource: resource, Action: action,
	}
	if err := s.CreatePermission(context.Background(), pm); err != nil {
		t.Fatalf("create permission %q: %v", name, err)
	}
	return pm
}

func TestPermissionsListPagesFiltersAndCounts(t *testing.T) {
	s := memory.New()
	seedPermission(t, s, "document:read", "document", "read")
	seedPermission(t, s, "document:write", "document", "write")
	seedPermission(t, s, "folder:read", "folder", "read")
	h := permissionsListHandler(Deps{Engine: engineOver(t, s)})

	all, err := h(context.Background(), PermissionsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.list: %v", err)
	}
	if all.Total != 3 {
		t.Errorf("total = %d, want 3", all.Total)
	}

	byResource, err := h(context.Background(), PermissionsListInput{Resource: "document"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("filtered: %v", err)
	}
	if byResource.Total != 2 {
		t.Errorf("resource=document total = %d, want 2", byResource.Total)
	}
	for _, item := range byResource.Items {
		if item.Resource != "document" {
			t.Errorf("resource filter leaked %q", item.Resource)
		}
	}
}

func TestPermissionsCreateRequiresNameToAgreeWithResourceAndAction(t *testing.T) {
	// The RBAC evaluator matches on Resource + ":" + Action, never on
	// Name. So a permission called document:read whose resource is folder
	// is invisible to every check that looks for document:read, and the
	// role that grants it appears to work and does not.
	s := memory.New()
	h := permissionsCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), PermissionCreateInput{
		Name: "document:read", Resource: "folder", Action: "read",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal when name disagrees with resource:action")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}

func TestPermissionsCreateDerivesNameWhenOmitted(t *testing.T) {
	// Name is derivable from resource and action, so asking for it twice
	// is a chance to disagree. An omitted name is filled in.
	s := memory.New()
	h := permissionsCreateHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PermissionCreateInput{
		Resource: "document", Action: "read",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.create: %v", err)
	}
	pid, err := id.ParsePermissionID(got.ID)
	if err != nil {
		t.Fatalf("bad id %q: %v", got.ID, err)
	}
	stored, err := s.GetPermission(context.Background(), "t1", pid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Name != "document:read" {
		t.Errorf("name = %q, want the derived document:read", stored.Name)
	}
}

func TestPermissionsCreateRequiresResourceAndAction(t *testing.T) {
	s := memory.New()
	h := permissionsCreateHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(context.Background(), PermissionCreateInput{Resource: "document"}, principalFor("t1")); err == nil {
		t.Error("want a refusal with no action")
	}
	if _, err := h(context.Background(), PermissionCreateInput{Action: "read"}, principalFor("t1")); err == nil {
		t.Error("want a refusal with no resource")
	}
}

func TestPermissionsUpdateLeavesOmittedFieldsAlone(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	pm := seedPermission(t, s, "document:read", "document", "read")
	pm.Description = "original"
	if err := s.UpdatePermission(ctx, pm); err != nil {
		t.Fatalf("seed description: %v", err)
	}
	h := permissionsUpdateHandler(Deps{Engine: engineOver(t, s)})

	// Update nothing at all: every field must survive.
	if _, err := h(ctx, PermissionUpdateInput{ID: pm.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("permissions.update: %v", err)
	}
	after, err := s.GetPermission(ctx, "t1", pm.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Description != "original" || after.Resource != "document" || after.Action != "read" {
		t.Errorf("an empty update changed something: %+v", after)
	}
}

func TestPermissionsUpdateRefusesASystemPermission(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	pm := &permission.Permission{
		TenantID: "t1", Name: "system:admin",
		Resource: "system", Action: "admin", IsSystem: true,
	}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := permissionsUpdateHandler(Deps{Engine: engineOver(t, s)})

	desc := "hijacked"
	if _, err := h(ctx, PermissionUpdateInput{ID: pm.ID.String(), Description: &desc}, principalFor("t1")); err == nil {
		t.Fatal("want a refusal updating a system permission")
	}
}

func TestPermissionsDeleteRefusesOneThatARoleStillGrants(t *testing.T) {
	// DeletePermission also removes the junction rows that grant it, so a
	// delete silently strips the permission from every role that had it.
	// Refuse and name the roles, so the operator detaches deliberately.
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := seedPermission(t, s, "document:read", "document", "read")
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: pm.Name}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := permissionsDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, PermissionDeleteInput{ID: pm.ID.String()}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal deleting a permission a role still grants")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("want CodeConflict, got %v", err)
	}
	if !containsText(ce.Message, "reader") {
		t.Errorf("message %q does not name the role holding it", ce.Message)
	}
	if _, getErr := s.GetPermission(ctx, "t1", pm.ID); getErr != nil {
		t.Errorf("the refusal did not prevent the delete: %v", getErr)
	}
}

func TestPermissionsDeleteRemovesAnUngrantedPermission(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	pm := seedPermission(t, s, "document:read", "document", "read")
	h := permissionsDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, PermissionDeleteInput{ID: pm.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("permissions.delete: %v", err)
	}
	if _, err := s.GetPermission(ctx, "t1", pm.ID); err == nil {
		t.Fatal("the permission is still there")
	}
}

func TestPermissionsDetailReturnsTheRolesThatGrantIt(t *testing.T) {
	// The question an operator actually has on this page is "who has this".
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := seedPermission(t, s, "document:read", "document", "read")
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: pm.Name}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := permissionsDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, PermissionDetailInput{ID: pm.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.detail: %v", err)
	}
	if len(got.GrantedBy) != 1 || got.GrantedBy[0].Slug != "reader" {
		t.Errorf("grantedBy = %+v, want the reader role", got.GrantedBy)
	}
}

// seedManyRoles creates n roles in t1 and returns the one the store lists
// last, so a test can put a grant past the first page without depending on
// how ids happen to order.
func seedManyRoles(t *testing.T, s *memory.Store, n int) *role.Role {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		slug := fmt.Sprintf("bulk-%03d", i)
		if err := s.CreateRole(ctx, &role.Role{TenantID: "t1", Name: slug, Slug: slug}); err != nil {
			t.Fatalf("create %s: %v", slug, err)
		}
	}
	all, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(all) != n {
		t.Fatalf("seeded %d roles, store lists %d", n, len(all))
	}
	return all[len(all)-1]
}

func TestPermissionsDeleteSeesAGrantPastTheFirstPageOfRoles(t *testing.T) {
	// The holder guard must not be bounded by a page size. With more roles
	// than one page holds, a permission granted only by the last role used
	// to look ungranted, so the delete went through and silently stripped
	// the grant from a role nobody was warned about.
	s := memory.New()
	ctx := context.Background()
	last := seedManyRoles(t, s, maxPageLimit+5)
	pm := seedPermission(t, s, "document:read", "document", "read")
	if err := s.AttachPermission(ctx, "t1", last.ID, permission.Ref{Name: pm.Name}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := permissionsDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, PermissionDeleteInput{ID: pm.ID.String()}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("want CodeConflict from a holder on page two, got %v", err)
	}
	if !containsText(ce.Message, last.Slug) {
		t.Errorf("message %q does not name %s", ce.Message, last.Slug)
	}
	if _, getErr := s.GetPermission(ctx, "t1", pm.ID); getErr != nil {
		t.Errorf("the refusal did not prevent the delete: %v", getErr)
	}
}

func TestPermissionsDetailGrantedByCoversEveryPageAndIsSorted(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	last := seedManyRoles(t, s, maxPageLimit+5)
	first, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Limit: 1})
	if err != nil || len(first) != 1 {
		t.Fatalf("first role: %v %d", err, len(first))
	}
	pm := seedPermission(t, s, "document:read", "document", "read")
	// Attach in reverse of the expected order so a map-range order would
	// have to be lucky to pass.
	for _, r := range []*role.Role{last, first[0]} {
		if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: pm.Name}); err != nil {
			t.Fatalf("attach %s: %v", r.Slug, err)
		}
	}
	h := permissionsDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, PermissionDetailInput{ID: pm.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.detail: %v", err)
	}
	slugs := make([]string, 0, len(got.GrantedBy))
	for _, r := range got.GrantedBy {
		slugs = append(slugs, r.Slug)
	}
	want := []string{first[0].Slug, last.Slug}
	sort.Strings(want)
	if !reflect.DeepEqual(slugs, want) {
		t.Errorf("grantedBy = %v, want %v (both pages, sorted by slug)", slugs, want)
	}
}

func TestPermissionsListIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	seedPermission(t, s, "mine:read", "mine", "read")
	if err := s.CreatePermission(ctx, &permission.Permission{
		TenantID: "t2", Name: "theirs:read", Resource: "theirs", Action: "read",
	}); err != nil {
		t.Fatalf("create other tenant's permission: %v", err)
	}
	h := permissionsListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, PermissionsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.list: %v", err)
	}
	// Identity, not count: a count assertion passes when the wrong rows
	// arrive in the right quantity.
	names := make([]string, 0, len(got.Items))
	for _, it := range got.Items {
		names = append(names, it.Name)
	}
	if !reflect.DeepEqual(names, []string{"mine:read"}) {
		t.Fatalf("t1 sees %v, want only mine:read (tenant scoping is not applied)", names)
	}
	if got.Total != 1 {
		t.Errorf("total = %d, want 1", got.Total)
	}
}

func TestPermissionsDetailGrantedByExcludesAnotherTenantsRoles(t *testing.T) {
	// t2 has a role granting a permission with the same name. It must not
	// appear as a holder of t1's permission, and must not block t1 deleting
	// it either.
	s := memory.New()
	ctx := context.Background()
	mine := seedRoles(t, s, "", "mine-role")[0]
	pm := seedPermission(t, s, "document:read", "document", "read")
	if err := s.AttachPermission(ctx, "t1", mine.ID, permission.Ref{Name: pm.Name}); err != nil {
		t.Fatalf("attach t1: %v", err)
	}
	theirs := &role.Role{TenantID: "t2", Name: "theirs-role", Slug: "theirs-role"}
	if err := s.CreateRole(ctx, theirs); err != nil {
		t.Fatalf("create t2 role: %v", err)
	}
	if err := s.CreatePermission(ctx, &permission.Permission{
		TenantID: "t2", Name: "document:read", Resource: "document", Action: "read",
	}); err != nil {
		t.Fatalf("create t2 permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t2", theirs.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach t2: %v", err)
	}
	h := permissionsDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, PermissionDetailInput{ID: pm.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.detail: %v", err)
	}
	slugs := make([]string, 0, len(got.GrantedBy))
	for _, r := range got.GrantedBy {
		slugs = append(slugs, r.Slug)
	}
	if !reflect.DeepEqual(slugs, []string{"mine-role"}) {
		t.Errorf("grantedBy = %v, want only mine-role (a t2 role leaked in)", slugs)
	}
}
