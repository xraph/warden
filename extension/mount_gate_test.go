package extension

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"
)

// With disable_routes, Register mounts nothing and needs no insecure opt-in
// (TestRegister_SucceedsWithRequireIdentityFalseWhenRoutesDisabled). These
// tests hold the gate at the places the API can still be mounted after
// that: Handler, RegisterRoutes, and the *api.API that API returns.

// routesOffExt registers an extension with routes disabled and
// auth.require_identity false, with or without the insecure opt-in.
func routesOffExt(t *testing.T, name string, optIn bool) *Extension {
	t.Helper()
	opts := []Option{
		WithStore(memory.New()),
		WithConfig(Config{Auth: AuthConfig{RequireIdentity: false, AuditLog: true}}),
		WithDisableRoutes(),
	}
	if optIn {
		opts = append(opts, WithInsecureAllowUnauthenticatedRoutes())
	}
	ext := New(opts...)
	if err := ext.Register(newTestApp(name)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return ext
}

// anonymousListRoles sends GET /v1/roles with a tenant in scope and no
// identity, and returns the status.
func anonymousListRoles(h http.Handler) int {
	ctx := warden.WithTenant(context.Background(), "app1", "t1")
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/roles", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestHandler_PanicsWithoutOptInWhenIdentityIsOff(t *testing.T) {
	ext := routesOffExt(t, "mount-a", false)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Handler handed out an API with require_identity false and no insecure opt-in; want a panic")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "WithInsecureAllowUnauthenticatedRoutes") {
			t.Fatalf("panic does not name the opt-in: %v", r)
		}
	}()
	ext.Handler()
}

func TestHandler_ServesWithoutIdentityWithOptIn(t *testing.T) {
	ext := routesOffExt(t, "mount-b", true)
	if code := anonymousListRoles(ext.Handler()); code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the opt-in skips the identity check", code)
	}
}

func TestRegisterRoutes_RefusesWithoutOptInWhenIdentityIsOff(t *testing.T) {
	ext := routesOffExt(t, "mount-c", false)
	router := forge.NewRouter()
	err := ext.RegisterRoutes(router)
	if err == nil {
		t.Fatal("RegisterRoutes mounted the API with require_identity false and no insecure opt-in; want an error")
	}
	if !strings.Contains(err.Error(), "WithInsecureAllowUnauthenticatedRoutes") {
		t.Fatalf("error does not name the opt-in: %v", err)
	}
	if code := anonymousListRoles(router.Handler()); code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: the refusal must register nothing", code)
	}
}

func TestRegisterRoutes_ServesWithoutIdentityWithOptIn(t *testing.T) {
	ext := routesOffExt(t, "mount-d", true)
	router := forge.NewRouter()
	if err := ext.RegisterRoutes(router); err != nil {
		t.Fatalf("RegisterRoutes: %v", err)
	}
	if code := anonymousListRoles(router.Handler()); code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the opt-in skips the identity check", code)
	}
}

// API() hands out the *api.API itself, which a caller can mount on a router
// of its own. Without the opt-in it still requires an identity.
func TestAPI_RequiresIdentityWithoutOptInWhenIdentityIsOff(t *testing.T) {
	ext := routesOffExt(t, "mount-e", false)
	router := forge.NewRouter()
	if err := ext.API().RegisterRoutes(router); err != nil {
		t.Fatalf("api RegisterRoutes: %v", err)
	}
	if code := anonymousListRoles(router.Handler()); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: no opt-in, so the identity check stays", code)
	}
}

func TestAPI_SkipsIdentityWithOptIn(t *testing.T) {
	ext := routesOffExt(t, "mount-f", true)
	router := forge.NewRouter()
	if err := ext.API().RegisterRoutes(router); err != nil {
		t.Fatalf("api RegisterRoutes: %v", err)
	}
	if code := anonymousListRoles(router.Handler()); code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the opt-in skips the identity check", code)
	}
}

// The secure default needs no opt-in on any mount path, and every one of
// them answers an anonymous caller 401.
func TestMountPaths_SecureDefaultRequiresIdentity(t *testing.T) {
	ext := New(WithStore(memory.New()), WithDisableRoutes())
	if err := ext.Register(newTestApp("mount-g")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if code := anonymousListRoles(ext.Handler()); code != http.StatusUnauthorized {
		t.Fatalf("Handler: status = %d, want 401", code)
	}
	router := forge.NewRouter()
	if err := ext.RegisterRoutes(router); err != nil {
		t.Fatalf("RegisterRoutes: %v", err)
	}
	if code := anonymousListRoles(router.Handler()); code != http.StatusUnauthorized {
		t.Fatalf("RegisterRoutes: status = %d, want 401", code)
	}
}
