package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedRoles creates n roles in tenant t1 at the given namespace.
func seedRoles(t *testing.T, s *memory.Store, namespace string, slugs ...string) []*role.Role {
	t.Helper()
	ctx := context.Background()
	out := make([]*role.Role, 0, len(slugs))
	for _, slug := range slugs {
		r := &role.Role{
			TenantID:      "t1",
			NamespacePath: namespace,
			Name:          slug,
			Slug:          slug,
		}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create role %q: %v", slug, err)
		}
		out = append(out, r)
	}
	return out
}

func engineOver(t *testing.T, s *memory.Store) *warden.Engine {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

func TestRolesListPagesAndReportsTheTotal(t *testing.T) {
	s := memory.New()
	seedRoles(t, s, "", "a", "b", "c", "d", "e")
	h := rolesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), RolesListInput{PageRequest: PageRequest{Limit: 2}}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.list: %v", err)
	}
	if len(got.Items) != 2 {
		t.Errorf("returned %d items, want 2", len(got.Items))
	}
	// Total is the count matching the filter, not the page size. A pager
	// that read len(items) would think there was one page.
	if got.Total != 5 {
		t.Errorf("total = %d, want 5", got.Total)
	}
	if got.Limit != 2 || got.Offset != 0 {
		t.Errorf("echoed limit/offset = %d/%d, want 2/0", got.Limit, got.Offset)
	}
}

func TestRolesListWithNoLimitDoesNotReturnEverything(t *testing.T) {
	// Every store ListFilter treats Limit 0 as no limit. A handler that
	// passed an unset limit straight through would load the whole table.
	s := memory.New()
	slugs := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		slugs = append(slugs, "r"+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	seedRoles(t, s, "", slugs...)
	h := rolesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), RolesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.list: %v", err)
	}
	if len(got.Items) != defaultPageLimit {
		t.Errorf("returned %d items, want the default page of %d", len(got.Items), defaultPageLimit)
	}
	if got.Total != 40 {
		t.Errorf("total = %d, want 40", got.Total)
	}
}

func TestRolesListFiltersByNamespaceAndDistinguishesRootFromAll(t *testing.T) {
	// The three-state namespace rule, on the server side. nil must mean
	// every namespace and "" must mean the tenant root, because the store
	// treats them differently and collapsing them would silently scope
	// every list to the root.
	s := memory.New()
	seedRoles(t, s, "", "root-role")
	seedRoles(t, s, "eng", "eng-role")
	h := rolesListHandler(Deps{Engine: engineOver(t, s)})

	all, err := h(context.Background(), RolesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if all.Total != 2 {
		t.Errorf("nil namespace total = %d, want both roles (2)", all.Total)
	}

	rootOnly := ""
	root, err := h(context.Background(), RolesListInput{NamespacePath: &rootOnly}, principalFor("t1"))
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if root.Total != 1 || root.Items[0].Slug != "root-role" {
		t.Errorf("empty-string namespace returned %+v, want only root-role", root.Items)
	}
}

func TestRolesListIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	seedRoles(t, s, "", "mine")
	ctx := context.Background()
	other := &role.Role{TenantID: "t2", Name: "theirs", Slug: "theirs"}
	if err := s.CreateRole(ctx, other); err != nil {
		t.Fatalf("create other tenant's role: %v", err)
	}
	h := rolesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, RolesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.list: %v", err)
	}
	// Asserted on identity, not count: a count assertion passes when the
	// wrong rows arrive in the right quantity.
	for _, r := range got.Items {
		if r.Slug == "theirs" {
			t.Fatal("t1 can see t2's role: tenant scoping is not applied")
		}
	}
	if got.Total != 1 {
		t.Errorf("total = %d, want 1", got.Total)
	}
}

func TestRolesDetailCarriesGrantsAndChildren(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	parent := seedRoles(t, s, "", "parent")[0]
	child := &role.Role{TenantID: "t1", Name: "child", Slug: "child", ParentSlug: "parent"}
	if err := s.CreateRole(ctx, child); err != nil {
		t.Fatalf("create child: %v", err)
	}
	p := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", parent.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := rolesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, RoleDetailInput{ID: parent.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.detail: %v", err)
	}
	if len(got.Permissions) != 1 || got.Permissions[0].Name != "document:read" {
		t.Errorf("permissions = %+v, want one document:read", got.Permissions)
	}
	if len(got.Children) != 1 || got.Children[0].Slug != "child" {
		t.Errorf("children = %+v, want one child", got.Children)
	}
}

func TestRolesDetailRejectsAMalformedID(t *testing.T) {
	// A typeid with the wrong prefix is a caller bug, not a missing row.
	// Reporting it as NOT_FOUND would send somebody looking for a role
	// that was never asked for.
	h := rolesDetailHandler(Deps{Engine: engineOver(t, memory.New())})
	_, err := h(context.Background(), RoleDetailInput{ID: "perm_01hq"}, principalFor("t1"))
	if err == nil {
		t.Fatal("want an error for a permission id passed as a role id")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}

func TestRolesDetailOfAnotherTenantsRoleIsNotFound(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	other := &role.Role{TenantID: "t2", Name: "theirs", Slug: "theirs"}
	if err := s.CreateRole(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := rolesDetailHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, RoleDetailInput{ID: other.ID.String()}, principalFor("t1"))
	if err == nil {
		t.Fatal("want NOT_FOUND reading another tenant's role by id")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Errorf("want CodeNotFound, got %v", err)
	}
}
