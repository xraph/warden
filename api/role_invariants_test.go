package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// The REST role and permission writes refuse what the dashboard contract
// refuses (extension/contract/immutable.go, handlers_roles.go checkParent),
// through the same shared checks: role.CheckWritable,
// permission.CheckWritable and role.CheckParent.

// wantRefusal fails unless rec has status code and carries message.
func wantRefusal(t *testing.T, rec *httptest.ResponseRecorder, code int, message string) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, code, rec.Body.String())
	}
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	decodeJSON(t, rec, &body)
	if body.Message != message && body.Error != message {
		t.Errorf("body = %s, want the message %q", rec.Body.String(), message)
	}
}

// systemFixture stores a system role "Admin" granting the system permission
// "sys:read" and the ordinary permission "doc:read", plus an ordinary
// permission "doc:write" nothing grants.
type systemFixture struct {
	s        *memory.Store
	h        http.Handler
	admin    *role.Role
	sysRead  *permission.Permission
	docRead  *permission.Permission
	docWrite *permission.Permission
}

func newSystemFixture(t *testing.T) *systemFixture {
	t.Helper()
	ctx := context.Background()
	f := &systemFixture{s: memory.New()}
	f.h = newTestAPIOver(t, &racingPolicyStore{Store: f.s})
	f.admin = &role.Role{TenantID: testTenant, Name: "Admin", Slug: "admin", IsSystem: true}
	if err := f.s.CreateRole(ctx, f.admin); err != nil {
		t.Fatalf("create role: %v", err)
	}
	mk := func(name, resource, action string, system bool) *permission.Permission {
		p := &permission.Permission{TenantID: testTenant, Name: name, Resource: resource, Action: action, IsSystem: system}
		if err := f.s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("create permission %s: %v", name, err)
		}
		return p
	}
	f.sysRead = mk("sys:read", "sys", "read", true)
	f.docRead = mk("doc:read", "doc", "read", false)
	f.docWrite = mk("doc:write", "doc", "write", false)
	for _, p := range []*permission.Permission{f.sysRead, f.docRead} {
		if err := f.s.AttachPermission(ctx, testTenant, f.admin.ID, permission.Ref{Name: p.Name}); err != nil {
			t.Fatalf("attach %s: %v", p.Name, err)
		}
	}
	return f
}

func (f *systemFixture) grants(t *testing.T) []string {
	t.Helper()
	held, err := f.s.ListRolePermissions(context.Background(), testTenant, f.admin.ID)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	names := make([]string, 0, len(held))
	for _, p := range held {
		names = append(names, p.Name)
	}
	return names
}

func TestRoles_SystemRoleWritesAre403(t *testing.T) {
	const want = `"Admin" is a system role and cannot be changed or deleted`
	cases := []struct {
		name string
		req  func(f *systemFixture) *http.Request
	}{
		{"update", func(f *systemFixture) *http.Request {
			return request(http.MethodPut, "/v1/roles/"+f.admin.ID.String(), "alice", testTenant,
				map[string]any{"name": "Renamed", "description": "changed"})
		}},
		{"delete", func(f *systemFixture) *http.Request {
			return request(http.MethodDelete, "/v1/roles/"+f.admin.ID.String(), "alice", testTenant, nil)
		}},
		{"attach by name", func(f *systemFixture) *http.Request {
			return request(http.MethodPost, "/v1/roles/"+f.admin.ID.String()+"/permissions", "alice", testTenant,
				map[string]any{"permission_name": "doc:write"})
		}},
		{"attach by id", func(f *systemFixture) *http.Request {
			return request(http.MethodPost, "/v1/roles/"+f.admin.ID.String()+"/permissions", "alice", testTenant,
				map[string]any{"permission_id": f.docWrite.ID.String()})
		}},
		{"detach", func(f *systemFixture) *http.Request {
			return request(http.MethodDelete,
				"/v1/roles/"+f.admin.ID.String()+"/permissions/"+f.docRead.ID.String(), "alice", testTenant, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSystemFixture(t)
			wantRefusal(t, do(f.h, tc.req(f)), http.StatusForbidden, want)

			after, err := f.s.GetRole(context.Background(), testTenant, f.admin.ID)
			if err != nil {
				t.Fatalf("the refusal removed the role: %v", err)
			}
			if after.Name != "Admin" || after.Description != "" {
				t.Errorf("the refusal wrote the role: name %q, description %q", after.Name, after.Description)
			}
			if got := strings.Join(f.grants(t), ","); got != "sys:read,doc:read" && got != "doc:read,sys:read" {
				t.Errorf("the refusal changed the grants: %s", got)
			}
		})
	}
}

func TestPermissions_SystemPermissionDeleteIs403(t *testing.T) {
	f := newSystemFixture(t)
	rec := do(f.h, request(http.MethodDelete, "/v1/permissions/"+f.sysRead.ID.String(), "alice", testTenant, nil))
	wantRefusal(t, rec, http.StatusForbidden, `"sys:read" is a system permission and cannot be changed or deleted`)
	if _, err := f.s.GetPermission(context.Background(), testTenant, f.sysRead.ID); err != nil {
		t.Fatalf("the refusal deleted the permission: %v", err)
	}
}

// The contract allows assigning a system role (BootstrapAdmin depends on
// it), and so does REST.
func TestAssignments_SystemRoleCanStillBeAssigned(t *testing.T) {
	f := newSystemFixture(t)
	rec := do(f.h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, map[string]any{
		"role_id": f.admin.ID.String(), "subject_kind": "user", "subject_id": "bob",
	}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}

// Ordinary roles and permissions are still writable through every route
// the guard sits on.
func TestRoles_OrdinaryWritesStillWork(t *testing.T) {
	f := newSystemFixture(t)
	ctx := context.Background()
	editor := &role.Role{TenantID: testTenant, Name: "Editor", Slug: "editor"}
	if err := f.s.CreateRole(ctx, editor); err != nil {
		t.Fatalf("create role: %v", err)
	}
	base := "/v1/roles/" + editor.ID.String()
	steps := []struct {
		name string
		req  *http.Request
		code int
	}{
		{"update", request(http.MethodPut, base, "alice", testTenant, map[string]any{"name": "Writer"}), http.StatusOK},
		{"attach", request(http.MethodPost, base+"/permissions", "alice", testTenant,
			map[string]any{"permission_name": "doc:write"}), http.StatusNoContent},
		{"detach", request(http.MethodDelete, base+"/permissions/"+f.docWrite.ID.String(), "alice", testTenant, nil),
			http.StatusNoContent},
		{"delete permission", request(http.MethodDelete, "/v1/permissions/"+f.docWrite.ID.String(), "alice", testTenant, nil),
			http.StatusNoContent},
		{"delete role", request(http.MethodDelete, base, "alice", testTenant, nil), http.StatusNoContent},
	}
	for _, st := range steps {
		if rec := do(f.h, st.req); rec.Code != st.code {
			t.Fatalf("%s: status = %d, want %d; body=%s", st.name, rec.Code, st.code, rec.Body.String())
		}
	}
	if _, err := f.s.GetRole(ctx, testTenant, editor.ID); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("role after delete: err = %v, want ErrRoleNotFound", err)
	}
}

// chain stores viewer <- editor <- owner (owner's parent is editor, whose
// parent is viewer) and returns viewer and owner.
func chain(t *testing.T, s *memory.Store) (viewer, owner *role.Role) {
	t.Helper()
	ctx := context.Background()
	viewer = &role.Role{TenantID: testTenant, Name: "Viewer", Slug: "viewer"}
	editor := &role.Role{TenantID: testTenant, Name: "Editor", Slug: "editor", ParentSlug: "viewer"}
	owner = &role.Role{TenantID: testTenant, Name: "Owner", Slug: "owner", ParentSlug: "editor"}
	for _, r := range []*role.Role{viewer, editor, owner} {
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create %s: %v", r.Slug, err)
		}
	}
	return viewer, owner
}

func TestRoles_ParentCycleIs400(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		want   string
	}{
		{"a descendant two levels down", "owner", "that parent would create a cycle in role inheritance"},
		{"a direct child", "editor", "that parent would create a cycle in role inheritance"},
		{"itself", "viewer", "a role cannot be its own parent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			h := newTestAPIOver(t, &racingPolicyStore{Store: s})
			viewer, _ := chain(t, s)
			rec := do(h, request(http.MethodPut, "/v1/roles/"+viewer.ID.String(), "alice", testTenant,
				map[string]any{"parent_slug": tc.parent, "name": "Renamed"}))
			wantRefusal(t, rec, http.StatusBadRequest, tc.want)
			after, err := s.GetRole(context.Background(), testTenant, viewer.ID)
			if err != nil {
				t.Fatalf("get role: %v", err)
			}
			if after.ParentSlug != "" || after.Name != "Viewer" {
				t.Errorf("the refusal wrote the role: parent %q, name %q", after.ParentSlug, after.Name)
			}
		})
	}
}

func TestRoles_CreateWithItselfAsParentIs400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Loop", "slug": "loop", "parent_slug": "loop",
	}))
	wantRefusal(t, rec, http.StatusBadRequest, "a role cannot be its own parent")
}

// A missing parent is 400 with a message that names no tenant.
func TestRoles_MissingParentIs400(t *testing.T) {
	s := memory.New()
	h := newTestAPIOver(t, &racingPolicyStore{Store: s})
	viewer, _ := chain(t, s)
	const want = "no role with slug ghost in this namespace"

	rec := do(h, request(http.MethodPut, "/v1/roles/"+viewer.ID.String(), "alice", testTenant,
		map[string]any{"parent_slug": "ghost"}))
	wantRefusal(t, rec, http.StatusBadRequest, want)

	rec = do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Orphan", "slug": "orphan", "parent_slug": "ghost",
	}))
	wantRefusal(t, rec, http.StatusBadRequest, want)
}

// Moving a role to a parent that is not one of its descendants still works,
// and so does clearing the parent.
func TestRoles_ParentChangesThatMakeNoCycleStillWork(t *testing.T) {
	s := memory.New()
	h := newTestAPIOver(t, &racingPolicyStore{Store: s})
	_, owner := chain(t, s)
	ctx := context.Background()

	if rec := do(h, request(http.MethodPut, "/v1/roles/"+owner.ID.String(), "alice", testTenant,
		map[string]any{"parent_slug": "viewer"})); rec.Code != http.StatusOK {
		t.Fatalf("reparent: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got, _ := s.GetRole(ctx, testTenant, owner.ID); got.ParentSlug != "viewer" {
		t.Errorf("owner's parent = %q, want viewer", got.ParentSlug)
	}
	if rec := do(h, request(http.MethodPut, "/v1/roles/"+owner.ID.String(), "alice", testTenant,
		map[string]any{"parent_slug": ""})); rec.Code != http.StatusOK {
		t.Fatalf("clear: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got, _ := s.GetRole(ctx, testTenant, owner.ID); got.ParentSlug != "" {
		t.Errorf("owner's parent = %q, want none", got.ParentSlug)
	}
	if rec := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Guest", "slug": "guest", "parent_slug": "viewer",
	})); rec.Code != http.StatusCreated {
		t.Fatalf("create with parent: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}
