package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"
)

// Fixed scope used across handler tests.
const (
	testApp     = "app1"
	testTenant  = "t1"
	otherTenant = "t2"
)

// allowAllAuthorizer is installed on the test API by default so handler
// tests (api/handlers_test.go) exercise handler logic: validation, store
// calls, actor capture, and audit emission, without also depending on a
// seeded role/permission graph. The real engine-backed default authorizer
// (allow/deny behavior) is covered separately in api/auth_test.go.
func allowAllAuthorizer(forge.Context, string, string) error { return nil }

// newTestAPI builds an API backed by a fresh memory store and registers
// its routes on a standalone forge.Router, returning the engine (for
// seeding fixtures directly through the store) and the assembled
// http.Handler. opts are applied after the allow-all authorizer default,
// so a caller can override it (e.g. api/auth_test.go passes a real
// authorizer or omits the override entirely to exercise defaultAuthorize).
func newTestAPI(t *testing.T, opts ...Option) http.Handler {
	t.Helper()
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	router := forge.NewRouter()
	allOpts := append([]Option{WithAuthorizer(allowAllAuthorizer)}, opts...)
	a := New(eng, router, allOpts...)
	if err := a.RegisterRoutes(router); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	return router.Handler()
}

// request builds an httptest.Request scoped as an authenticated caller
// (unless userID is "") in tenantID, with an optional JSON body. It
// mirrors what an upstream Forge auth layer + the request's own scope
// resolution would set up before the request reaches warden's routes:
// forge.WithUserID feeds warden.ActorFromContext's fallback chain, and
// warden.WithTenant feeds scopeFromForgeContext / requireScope.
func request(method, path, userID, tenantID string, body any) *http.Request {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		reader = bytes.NewReader(b)
	}
	ctx := context.Background()
	if userID != "" {
		ctx = forge.WithUserID(ctx, userID)
	}
	if tenantID != "" {
		ctx = warden.WithTenant(ctx, testApp, tenantID)
	}
	req := httptest.NewRequestWithContext(ctx, method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// do drives h with req and returns the recorder.
func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeJSON unmarshals rec's body into v, failing the test on error.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
}
