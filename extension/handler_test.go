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

// Handler builds warden's API on a router of its own. These tests hold
// that it serves warden's routes and nothing else, leaves the app's
// router alone, can be called twice, and sits beside the base-path mount
// Register makes when routes are enabled.

// get sends an anonymous GET with a tenant in scope and returns the status.
func get(h http.Handler, path string) int {
	ctx := warden.WithTenant(context.Background(), "app1", "t1")
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func ok(ctx forge.Context) error { return ctx.String(http.StatusOK, "ok") }

// routePaths lists the method and path of every route on the router.
func routePaths(r forge.Router) []string {
	routes := r.Routes()
	out := make([]string, 0, len(routes))
	for _, ri := range routes {
		out = append(out, ri.Method+" "+ri.Path)
	}
	return out
}

func TestHandler_ServesWardenRoutesAndNothingElse(t *testing.T) {
	app := newTestApp("handler-a")
	if err := app.Router().GET("/ping", ok); err != nil {
		t.Fatalf("app route: %v", err)
	}
	ext := New(WithStore(memory.New()), WithDisableRoutes())
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h := ext.Handler()

	// The route exists and runs warden's identity check.
	if code := get(h, "/v1/roles"); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/roles: status = %d, want 401", code)
	}
	// The caller picks the prefix, as the doc comment says.
	if code := get(http.StripPrefix("/authz", h), "/authz/v1/roles"); code != http.StatusUnauthorized {
		t.Fatalf("GET /authz/v1/roles through StripPrefix: status = %d, want 401", code)
	}
	// No base path, and none of the app's routes.
	for _, path := range []string{"/warden/v1/roles", "/ping", "/"} {
		if code := get(h, path); code != http.StatusNotFound {
			t.Fatalf("GET %s: status = %d, want 404 from warden's own router", path, code)
		}
	}
}

func TestHandler_AddsNothingToTheAppRouter(t *testing.T) {
	app := newTestApp("handler-b")
	if err := app.Router().GET("/before", ok); err != nil {
		t.Fatalf("app route: %v", err)
	}
	ext := New(WithStore(memory.New()), WithDisableRoutes())
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	before := routePaths(app.Router())

	ext.Handler()

	after := routePaths(app.Router())
	if strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("Handler changed the app router's routes:\nbefore %v\nafter  %v", before, after)
	}
	// Routes registered after Handler must not pick up warden's
	// identity, scope or IP middleware either.
	if err := app.Router().GET("/after", ok); err != nil {
		t.Fatalf("app route: %v", err)
	}
	appHandler := app.Router().Handler()
	for _, path := range []string{"/before", "/after"} {
		if code := get(appHandler, path); code != http.StatusOK {
			t.Fatalf("app GET %s: status = %d, want 200: no warden middleware on the app router", path, code)
		}
	}
	if code := get(appHandler, "/v1/roles"); code != http.StatusNotFound {
		t.Fatalf("app GET /v1/roles: status = %d, want 404", code)
	}
}

func TestHandler_CalledTwiceServesTheSameAPI(t *testing.T) {
	ext := New(WithStore(memory.New()), WithDisableRoutes())
	if err := ext.Register(newTestApp("handler-c")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	first := ext.Handler()
	second := ext.Handler()
	for i, h := range []http.Handler{first, second} {
		if code := get(h, "/v1/roles"); code != http.StatusUnauthorized {
			t.Fatalf("call %d: GET /v1/roles: status = %d, want 401", i+1, code)
		}
	}
}

func TestHandler_LeavesTheBasePathMountAlone(t *testing.T) {
	app := newTestApp("handler-d")
	ext := New(WithStore(memory.New()))
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	before := routePaths(app.Router())

	h := ext.Handler()

	after := routePaths(app.Router())
	if strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("Handler changed the app router's routes:\nbefore %v\nafter  %v", before, after)
	}
	seen := 0
	for _, p := range after {
		if p == "GET /warden/v1/roles" {
			seen++
		}
		if strings.HasPrefix(p, "GET /v1/") || strings.HasPrefix(p, "POST /v1/") {
			t.Fatalf("app router has a warden route outside the base path: %s", p)
		}
	}
	if seen != 1 {
		t.Fatalf("GET /warden/v1/roles registered %d times on the app router, want 1", seen)
	}
	if code := get(app.Router().Handler(), "/warden/v1/roles"); code != http.StatusUnauthorized {
		t.Fatalf("app GET /warden/v1/roles: status = %d, want 401", code)
	}
	if code := get(h, "/v1/roles"); code != http.StatusUnauthorized {
		t.Fatalf("Handler GET /v1/roles: status = %d, want 401", code)
	}
}
