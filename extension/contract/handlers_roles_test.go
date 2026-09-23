package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
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

func TestRolesCreateReturnsTheNewID(t *testing.T) {
	s := memory.New()
	h := rolesCreateHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), RoleCreateInput{
		Name: "Reader", Slug: "reader", Description: "can read",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.create: %v", err)
	}
	if got.ID == "" {
		t.Fatal("create returned no id: the page cannot navigate to what it made")
	}
	rid, err := id.ParseRoleID(got.ID)
	if err != nil {
		t.Fatalf("returned id %q is not a role id: %v", got.ID, err)
	}
	stored, err := s.GetRole(context.Background(), "t1", rid)
	if err != nil {
		t.Fatalf("get created role: %v", err)
	}
	if stored.Name != "Reader" || stored.Slug != "reader" {
		t.Errorf("stored %+v, want name Reader slug reader", stored)
	}
}

func TestRolesCreateRejectsAnInvalidNamespace(t *testing.T) {
	// ValidateNamespacePath forbids a leading or trailing slash and caps
	// depth. A bad namespace must be refused here rather than written and
	// then be unreachable by every namespaced query.
	s := memory.New()
	h := rolesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), RoleCreateInput{
		Name: "X", Slug: "x", NamespacePath: "/leading",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal for a namespace with a leading slash")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}

func TestRolesUpdateLeavesOmittedFieldsAlone(t *testing.T) {
	// The trap. UpdateRole takes a whole *role.Role and writes it, so a
	// handler that builds a fresh struct from the request erases every
	// field the request did not mention. Here: update only the name, and
	// the description, parent and member cap must survive.
	s := memory.New()
	ctx := context.Background()
	seedRoles(t, s, "", "base")
	r := &role.Role{
		TenantID: "t1", Name: "Original", Slug: "target",
		Description: "keep me", ParentSlug: "base", MaxMembers: 7,
	}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	newName := "Renamed"
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), Name: &newName}, principalFor("t1")); err != nil {
		t.Fatalf("roles.update: %v", err)
	}

	after, err := s.GetRole(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Name != "Renamed" {
		t.Errorf("name = %q, want Renamed", after.Name)
	}
	if after.Description != "keep me" {
		t.Errorf("description = %q, want it untouched", after.Description)
	}
	if after.ParentSlug != "base" {
		t.Errorf("parentSlug = %q, want it untouched", after.ParentSlug)
	}
	if after.MaxMembers != 7 {
		t.Errorf("maxMembers = %d, want it untouched", after.MaxMembers)
	}
}

func TestRolesUpdateCanClearAFieldDeliberately(t *testing.T) {
	// The other half of the pointer contract: a pointer to the empty
	// string means "set it to empty", which is different from omitting it.
	s := memory.New()
	ctx := context.Background()
	seedRoles(t, s, "", "base")
	r := &role.Role{TenantID: "t1", Name: "R", Slug: "target", ParentSlug: "base"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	empty := ""
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), ParentSlug: &empty}, principalFor("t1")); err != nil {
		t.Fatalf("roles.update: %v", err)
	}
	after, err := s.GetRole(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.ParentSlug != "" {
		t.Errorf("parentSlug = %q, want cleared", after.ParentSlug)
	}
}

func TestRolesUpdateRefusesASystemRole(t *testing.T) {
	// Nothing below the contract enforces this. See immutable.go.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "System", Slug: "system-role", IsSystem: true}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	newName := "Hijacked"
	_, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), Name: &newName}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal updating a system role")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
		t.Errorf("want CodePermissionDenied, got %v", err)
	}
	after, getErr := s.GetRole(ctx, "t1", r.ID)
	if getErr != nil {
		t.Fatalf("get: %v", getErr)
	}
	if after.Name != "System" {
		t.Errorf("the refusal did not prevent the write: name is now %q", after.Name)
	}
}

func TestRolesUpdateRefusesAParentCycle(t *testing.T) {
	// Setting a role's parent to its own descendant makes the engine's
	// inheritance walk loop. ErrCyclicRoleInheritance exists for this.
	s := memory.New()
	ctx := context.Background()
	parent := &role.Role{TenantID: "t1", Name: "P", Slug: "p"}
	if err := s.CreateRole(ctx, parent); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	child := &role.Role{TenantID: "t1", Name: "C", Slug: "c", ParentSlug: "p"}
	if err := s.CreateRole(ctx, child); err != nil {
		t.Fatalf("create child: %v", err)
	}
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	cycle := "c"
	_, err := h(ctx, RoleUpdateInput{ID: parent.ID.String(), ParentSlug: &cycle}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal setting a role's parent to its own child")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest for a cycle, got %v", err)
	}
}

func TestRolesUpdateRefusesARoleAsItsOwnParent(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "R", Slug: "self"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	self := "self"
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), ParentSlug: &self}, principalFor("t1")); err == nil {
		t.Fatal("want a refusal for a role parented to itself")
	}
}

func TestRolesDeleteRemovesTheRole(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "doomed")[0]
	h := rolesDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RoleDeleteInput{ID: r.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("roles.delete: %v", err)
	}
	if _, err := s.GetRole(ctx, "t1", r.ID); err == nil {
		t.Fatal("the role is still there after delete")
	}
}

func TestRolesDeleteRefusesASystemRole(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "System", Slug: "sys", IsSystem: true}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := rolesDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RoleDeleteInput{ID: r.ID.String()}, principalFor("t1")); err == nil {
		t.Fatal("want a refusal deleting a system role")
	}
	if _, err := s.GetRole(ctx, "t1", r.ID); err != nil {
		t.Errorf("the refusal did not prevent the delete: %v", err)
	}
}

func TestRolesAttachPermissionGrantsIt(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	h := rolesAttachPermissionHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RolePermissionInput{
		RoleID: r.ID.String(), PermissionName: "document:read",
	}, principalFor("t1")); err != nil {
		t.Fatalf("roles.attachPermission: %v", err)
	}
	grants, err := s.ListRolePermissions(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(grants) != 1 || grants[0].Name != "document:read" {
		t.Errorf("grants = %+v, want one document:read", grants)
	}
}

func TestRolesAttachPermissionThatDoesNotExistIsRefused(t *testing.T) {
	// The junction is keyed by (namespacePath, name) and the store will
	// happily record a grant for a permission that is not there, which
	// then grants nothing and looks like it worked. Resolve it first.
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	h := rolesAttachPermissionHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, RolePermissionInput{
		RoleID: r.ID.String(), PermissionName: "nope:nope",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal attaching a permission that does not exist")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Errorf("want CodeNotFound, got %v", err)
	}
}

func TestRolesDetachPermissionThatWasNeverAttachedIsRefused(t *testing.T) {
	// A detach with the wrong namespace silently affects nothing and
	// returns no error, so the page would report success and the grant
	// would still be there. Verify the grant exists before detaching.
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	h := rolesDetachPermissionHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, RolePermissionInput{
		RoleID: r.ID.String(), PermissionName: "document:read",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal detaching a grant the role does not have")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Errorf("want CodeNotFound, got %v", err)
	}
}

func TestRolesDetachPermissionRemovesTheGrant(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := rolesDetachPermissionHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RolePermissionInput{
		RoleID: r.ID.String(), PermissionName: "document:read",
	}, principalFor("t1")); err != nil {
		t.Fatalf("roles.detachPermission: %v", err)
	}
	grants, err := s.ListRolePermissions(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("grants = %+v, want none", grants)
	}
}

func TestRolesSetPermissionsReplacesTheWholeSet(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	for _, p := range []struct{ name, resource, action string }{
		{"document:read", "document", "read"},
		{"document:write", "document", "write"},
		{"folder:read", "folder", "read"},
	} {
		pm := &permission.Permission{
			TenantID: "t1", Name: p.name, Resource: p.resource, Action: p.action,
		}
		if err := s.CreatePermission(ctx, pm); err != nil {
			t.Fatalf("create %q: %v", p.name, err)
		}
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := rolesSetPermissionsHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RoleSetPermissionsInput{
		RoleID: r.ID.String(),
		Permissions: []PermissionRef{
			{Name: "document:write"},
			{Name: "folder:read"},
		},
	}, principalFor("t1")); err != nil {
		t.Fatalf("roles.setPermissions: %v", err)
	}
	grants, err := s.ListRolePermissions(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants = %+v, want exactly the two named", grants)
	}
	for _, g := range grants {
		if g.Name == "document:read" {
			t.Error("setPermissions did not replace: the old grant survived")
		}
	}
}

func TestRolesSetPermissionsToAnEmptyListRevokesEverything(t *testing.T) {
	// An empty list is a real instruction, not a missing one: it means
	// this role grants nothing. A handler that treated empty as "no
	// change" would make revoke-all impossible from the UI.
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := rolesSetPermissionsHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RoleSetPermissionsInput{
		RoleID: r.ID.String(), Permissions: []PermissionRef{},
	}, principalFor("t1")); err != nil {
		t.Fatalf("roles.setPermissions: %v", err)
	}
	grants, err := s.ListRolePermissions(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("grants = %+v, want none after an empty set", grants)
	}
}

func TestRolesSetPermissionsRefusesAnUnknownPermission(t *testing.T) {
	// All or nothing. Silently dropping the unknown names would leave the
	// role with a set the operator did not choose.
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	pm := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	h := rolesSetPermissionsHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, RoleSetPermissionsInput{
		RoleID:      r.ID.String(),
		Permissions: []PermissionRef{{Name: "document:read"}, {Name: "ghost:read"}},
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal when one named permission does not exist")
	}
	grants, listErr := s.ListRolePermissions(ctx, "t1", r.ID)
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	if len(grants) != 1 {
		t.Errorf("the refused call changed the grants anyway: %+v", grants)
	}
}

func TestJunctionCommandsRefuseASystemRole(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "System", Slug: "sys", IsSystem: true}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	pm := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	deps := Deps{Engine: engineOver(t, s)}

	if _, err := rolesAttachPermissionHandler(deps)(ctx, RolePermissionInput{
		RoleID: r.ID.String(), PermissionName: "document:read",
	}, principalFor("t1")); err == nil {
		t.Error("attach to a system role must be refused")
	}
	if _, err := rolesSetPermissionsHandler(deps)(ctx, RoleSetPermissionsInput{
		RoleID: r.ID.String(), Permissions: []PermissionRef{},
	}, principalFor("t1")); err == nil {
		t.Error("setPermissions on a system role must be refused")
	}
}
