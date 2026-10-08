package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"
)

// Handler registers the routes once. A second call used to register them
// again on the same router, which the router refuses with a panic.
func TestAPIHandler_CalledTwiceRegistersOnce(t *testing.T) {
	eng, err := warden.NewEngine(warden.WithStore(memory.New()))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	a := New(eng, nil)
	first := a.Handler()
	second := a.Handler()
	if first != second {
		t.Fatal("second Handler call built a new handler; want the first one back")
	}
	rec := httptest.NewRecorder()
	second.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/roles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/roles: status = %d, want 401", rec.Code)
	}
}

// handlerPanic calls Handler and returns what it panicked with, or "" when
// it returned.
func handlerPanic(a *API) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	a.Handler()
	return ""
}

// A registration that fails partway leaves the router half registered. A
// second Handler call must report that same failure, not run the
// registration again and trip over the routes the first call left behind.
func TestAPIHandler_FailedRegistrationFailsTheSameEveryCall(t *testing.T) {
	eng, err := warden.NewEngine(warden.WithStore(memory.New()))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	router := forge.NewRouter()
	// The last route RegisterRoutes adds, taken already, so every route
	// before it is registered when it fails.
	if err := router.GET("/v1/check-logs", func(ctx forge.Context) error { return nil }); err != nil {
		t.Fatalf("pre-register: %v", err)
	}
	a := New(eng, router)

	first := handlerPanic(a)
	if first == "" {
		t.Fatal("first Handler call returned; want a panic for the route conflict")
	}
	if !strings.Contains(first, "check-logs") {
		t.Fatalf("first panic = %q, want the check-logs conflict", first)
	}
	for i := 2; i <= 3; i++ {
		if got := handlerPanic(a); got != first {
			t.Fatalf("call %d panicked with %q, want the first error %q", i, got, first)
		}
	}
}
