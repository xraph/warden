package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

func TestRequireIdentity_NoActor401(t *testing.T) {
	h := newTestAPI(t)

	rec := do(h, request(http.MethodGet, "/v1/roles?search=&limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireIdentity_WithActorPasses(t *testing.T) {
	h := newTestAPI(t)

	rec := do(h, request(http.MethodGet, "/v1/roles?search=&limit=10&offset=0", "alice", testTenant, nil))
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("status = 401 with an actor set; body=%s", rec.Body.String())
	}
}

func TestRequireIdentity_AllowAnonymousChecks_OnlyChecksExempt(t *testing.T) {
	h := newTestAPI(t, AllowAnonymousChecks())

	checkBody := map[string]any{"subject_id": "u1", "action": "read", "resource_type": "document"}
	rec := do(h, request(http.MethodPost, "/v1/authz/check", "", testTenant, checkBody))
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("check endpoint: status = 401 with AllowAnonymousChecks; body=%s", rec.Body.String())
	}

	// A non-check route must still require identity even with
	// AllowAnonymousChecks set: the option is narrowly scoped to the
	// three check endpoints.
	rec2 := do(h, request(http.MethodGet, "/v1/roles?search=&limit=10&offset=0", "", testTenant, nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("roles list: status = %d, want 401 (AllowAnonymousChecks must not exempt it); body=%s", rec2.Code, rec2.Body.String())
	}

	// AuthZEN is also not one of "the three check endpoints" and must
	// still require identity.
	rec3 := do(h, request(http.MethodPost, "/access/v1/evaluation", "", testTenant, map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u1"},
		"action":   map[string]any{"name": "read"},
		"resource": map[string]any{"type": "document", "id": "d1"},
	}))
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("authzen evaluation: status = %d, want 401; body=%s", rec3.Code, rec3.Body.String())
	}
}

func TestRequireScope_NoTenant400(t *testing.T) {
	h := newTestAPI(t)

	rec := do(h, request(http.MethodGet, "/v1/roles?search=&limit=10&offset=0", "alice", "", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestWithInsecureAllowUnauthenticatedRoutes_SkipsIdentityAndAuthorize(t *testing.T) {
	h := newTestAPI(t, WithInsecureAllowUnauthenticatedRoutes())

	rec := do(h, request(http.MethodGet, "/v1/roles?search=&limit=10&offset=0", "", testTenant, nil))
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("status = %d with the insecure escape hatch set; want neither 401 nor 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDefaultAuthorize_AllowsGrantedDeniesUngranted exercises the real
// engine-backed default authorizer (no WithAuthorizer override): an actor
// with a role granting warden:role:manage may create a role; an actor
// with no roles at all gets 403.
func TestDefaultAuthorize_AllowsGrantedDeniesUngranted(t *testing.T) {
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	now := time.Now()
	r := &role.Role{
		ID: id.NewRoleID(), TenantID: testTenant, Name: "admin", Slug: "admin",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateRole(t.Context(), r); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	p := &permission.Permission{
		ID: id.NewPermissionID(), TenantID: testTenant, Name: "warden:role:manage",
		Resource: "warden:role", Action: "manage", CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreatePermission(t.Context(), p); err != nil {
		t.Fatalf("seed permission: %v", err)
	}
	if err := s.AttachPermission(t.Context(), testTenant, r.ID, permission.Ref{Name: p.Name}); err != nil {
		t.Fatalf("attach permission: %v", err)
	}
	if err := s.CreateAssignment(t.Context(), &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: testTenant, RoleID: r.ID,
		SubjectKind: "user", SubjectID: "granted-user", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	router := forge.NewRouter()
	a := New(eng, router)
	if err := a.RegisterRoutes(router); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	h := router.Handler()

	body := map[string]any{"name": "Editor", "slug": "editor"}

	allowed := do(h, request(http.MethodPost, "/v1/roles", "granted-user", testTenant, body))
	if allowed.Code != http.StatusCreated {
		t.Fatalf("granted user: status = %d, want 201; body=%s", allowed.Code, allowed.Body.String())
	}

	denied := do(h, request(http.MethodPost, "/v1/roles", "ungranted-user", testTenant, body))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("ungranted user: status = %d, want 403; body=%s", denied.Code, denied.Body.String())
	}
}
