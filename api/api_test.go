package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
