package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/memory"
)

const (
	testApp    = "app1"
	testTenant = "t1"
)

// newGuardedRouter mounts a single GET /guarded route behind mw and
// returns the assembled handler.
func newGuardedRouter(mw forge.Middleware) http.Handler {
	router := forge.NewRouter()
	_ = router.GET("/guarded", func(ctx forge.Context) error {
		return ctx.String(http.StatusOK, "ok")
	}, forge.WithMiddleware(mw))
	return router.Handler()
}

func newRequest(userID, tenantID string) *http.Request {
	ctx := context.Background()
	if userID != "" {
		ctx = forge.WithUserID(ctx, userID)
	}
	if tenantID != "" {
		ctx = warden.WithTenant(ctx, testApp, tenantID)
	}
	return httptest.NewRequestWithContext(ctx, http.MethodGet, "/guarded", nil)
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// seedGranted builds a memory-backed engine with a role granting
// "read" on "document" to user "granted-user".
func seedGranted(t *testing.T) *warden.Engine {
	t.Helper()
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	now := time.Now()
	r := &role.Role{ID: id.NewRoleID(), TenantID: testTenant, Name: "reader", Slug: "reader", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateRole(t.Context(), r); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	p := &permission.Permission{ID: id.NewPermissionID(), TenantID: testTenant, Name: "document:read", Resource: "document", Action: "read", CreatedAt: now, UpdatedAt: now}
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
	return eng
}

func TestRequire_Allow(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(Require(eng, "read", "document"))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q (next handler must run on allow)", rec.Body.String(), "ok")
	}
}

func TestRequire_Deny(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(Require(eng, "read", "document"))

	rec := do(h, newRequest("ungranted-user", testTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequire_AnonymousDefault401(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(Require(eng, "read", "document"))

	// No forge.WithUserID set: no identity resolves. Default behavior
	// (no AllowAnonymous) must reject before the engine is ever
	// consulted, not silently evaluate as some fabricated subject.
	rec := do(h, newRequest("", testTenant))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequire_AllowAnonymousOption(t *testing.T) {
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	now := time.Now()
	r := &role.Role{ID: id.NewRoleID(), TenantID: testTenant, Name: "reader", Slug: "reader", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateRole(t.Context(), r); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	p := &permission.Permission{ID: id.NewPermissionID(), TenantID: testTenant, Name: "document:read", Resource: "document", Action: "read", CreatedAt: now, UpdatedAt: now}
	if err := s.CreatePermission(t.Context(), p); err != nil {
		t.Fatalf("seed permission: %v", err)
	}
	if err := s.AttachPermission(t.Context(), testTenant, r.ID, permission.Ref{Name: p.Name}); err != nil {
		t.Fatalf("attach permission: %v", err)
	}
	// Grant the fixed "anonymous" subject the role, so AllowAnonymous's
	// explicit fallback subject (not an attacker-chosen one) can be
	// authorized.
	if err := s.CreateAssignment(t.Context(), &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: testTenant, RoleID: r.ID,
		SubjectKind: "user", SubjectID: "anonymous", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	h := newGuardedRouter(Require(eng, "read", "document", AllowAnonymous()))
	rec := do(h, newRequest("", testTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with AllowAnonymous set and the anonymous subject granted; body=%s", rec.Code, rec.Body.String())
	}
}

// erroringRoleListStore wraps a real store.Store, failing only
// ListRolesForSubject, to drive Require's "store error -> 503" path
// deterministically: the engine's RBAC resolution calls this first, so
// failing it surfaces as a genuine evaluation error rather than a deny.
type erroringRoleListStore struct {
	store.Store
}

func (erroringRoleListStore) ListRolesForSubject(context.Context, string, []string, string, string) ([]id.RoleID, error) {
	return nil, errors.New("simulated store outage")
}

func TestRequire_StoreError503(t *testing.T) {
	eng, err := warden.NewEngine(warden.WithStore(erroringRoleListStore{Store: memory.New()}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	h := newGuardedRouter(Require(eng, "read", "document"))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequire_NoTenant400(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(Require(eng, "read", "document"))

	rec := do(h, newRequest("granted-user", ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (ErrTenantRequired); body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireAny_AllowsOnFirstMatch(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(RequireAny(eng, []warden.CheckRequest{
		{Action: warden.Action{Name: "write"}, Resource: warden.Resource{Type: "document"}},
		{Action: warden.Action{Name: "read"}, Resource: warden.Resource{Type: "document"}},
	}))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireAny_DeniesWhenNoneMatch(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(RequireAny(eng, []warden.CheckRequest{
		{Action: warden.Action{Name: "write"}, Resource: warden.Resource{Type: "document"}},
	}))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireAll_AllowsWhenAllMatch(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(RequireAll(eng, []warden.CheckRequest{
		{Action: warden.Action{Name: "read"}, Resource: warden.Resource{Type: "document"}},
	}))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireAll_DeniesWhenAnyFails(t *testing.T) {
	eng := seedGranted(t)
	h := newGuardedRouter(RequireAll(eng, []warden.CheckRequest{
		{Action: warden.Action{Name: "read"}, Resource: warden.Resource{Type: "document"}},
		{Action: warden.Action{Name: "write"}, Resource: warden.Resource{Type: "document"}},
	}))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestWithContext_MergedIntoCheckRequest(t *testing.T) {
	// WithContext's fn output feeds warden.CheckRequest.Context; the
	// simplest observable proof without a policy engine wired up is that
	// it doesn't break the allow path and fn is actually invoked.
	eng := seedGranted(t)
	called := false
	opt := WithContext(func(forge.Context) map[string]any {
		called = true
		return map[string]any{"ip": "10.0.0.1"}
	})
	h := newGuardedRouter(Require(eng, "read", "document", opt))

	rec := do(h, newRequest("granted-user", testTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatal("WithContext's fn was never invoked")
	}
}

func TestRequestIP_PrefersForwardedFor(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/guarded", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	req.RemoteAddr = "192.0.2.1:12345"

	// requestIP takes a forge.Context; drive it through a minimal
	// middleware invocation to get one instead of constructing a
	// forge.Context by hand (unexported concrete type).
	var got string
	h := newGuardedRouter(func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			got = requestIP(ctx)
			return next(ctx)
		}
	})
	do(h, req)
	if got != "203.0.113.5" {
		t.Fatalf("requestIP = %q, want first X-Forwarded-For hop %q", got, "203.0.113.5")
	}
}

func TestRequestIP_FallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/guarded", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	var got string
	h := newGuardedRouter(func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			got = requestIP(ctx)
			return next(ctx)
		}
	})
	do(h, req)
	if got != "192.0.2.1" {
		t.Fatalf("requestIP = %q, want %q", got, "192.0.2.1")
	}
}
