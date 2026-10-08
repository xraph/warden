package api

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// racingPolicyStore lands a write between the update handler's read and its
// write, which cannot be interleaved from outside: race runs once, right
// after the first GetPolicy returns.
type racingPolicyStore struct {
	*memory.Store
	mu   sync.Mutex
	race func()
}

func (r *racingPolicyStore) GetPolicy(ctx context.Context, tenantID string, pid id.PolicyID) (*policy.Policy, error) {
	got, err := r.Store.GetPolicy(ctx, tenantID, pid)
	r.mu.Lock()
	race := r.race
	r.race = nil
	r.mu.Unlock()
	if race != nil && err == nil {
		race()
	}
	return got, err
}

// newTestAPIOver is newTestAPI over a store the test holds.
func newTestAPIOver(t *testing.T, s *racingPolicyStore) http.Handler {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	router := forge.NewRouter()
	a := New(eng, router, WithAuthorizer(allowAllAuthorizer))
	if err := a.RegisterRoutes(router); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	return router.Handler()
}

func createPolicyOver(t *testing.T, h http.Handler) id.PolicyID {
	t.Helper()
	create := do(h, request(http.MethodPost, "/v1/policies", "alice", testTenant, map[string]any{
		"name": "allow-read", "effect": "allow", "is_active": true,
	}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, create, &created)
	pid, err := id.ParsePolicyID(created.ID)
	if err != nil {
		t.Fatalf("parse created id: %v", err)
	}
	return pid
}

func storedPolicyIn(t *testing.T, s *memory.Store, pid id.PolicyID) *policy.Policy {
	t.Helper()
	got, err := s.GetPolicy(context.Background(), testTenant, pid)
	if err != nil {
		t.Fatalf("stored policy: %v", err)
	}
	return got
}

func TestPolicies_UpdateStoresTheNextVersion(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	pid := createPolicyOver(t, h)
	before := storedPolicyIn(t, s.Store, pid)

	update := do(h, request(http.MethodPut, "/v1/policies/"+pid.String(), "alice", testTenant, map[string]any{
		"description": "updated",
	}))
	if update.Code != http.StatusOK {
		t.Fatalf("update: status = %d, want 200; body=%s", update.Code, update.Body.String())
	}
	after := storedPolicyIn(t, s.Store, pid)
	if after.Description != "updated" || after.Version != before.Version+1 {
		t.Errorf("stored description/version = %q/%d, want updated/%d", after.Description, after.Version, before.Version+1)
	}
}

// A write landing between the update's read and its write answers 409 and
// keeps the other write, rather than silently undoing it.
func TestPolicies_UpdateRacingAnotherWriteIs409(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	pid := createPolicyOver(t, h)

	var moved *policy.Policy
	s.race = func() {
		cur := storedPolicyIn(t, s.Store, pid)
		next := *cur
		next.Description = "changed out of band"
		next.Version = cur.Version + 1
		if err := s.UpdatePolicyIfVersion(context.Background(), &next, cur.Version); err != nil {
			t.Errorf("out-of-band write: %v", err)
		}
		moved = storedPolicyIn(t, s.Store, pid)
	}

	update := do(h, request(http.MethodPut, "/v1/policies/"+pid.String(), "alice", testTenant, map[string]any{
		"description": "my edit",
	}))
	if update.Code != http.StatusConflict {
		t.Fatalf("update: status = %d, want 409; body=%s", update.Code, update.Body.String())
	}
	if moved == nil {
		t.Fatal("the race never ran")
	}
	if got := storedPolicyIn(t, s.Store, pid); !reflect.DeepEqual(got, moved) {
		t.Errorf("the other write was not kept:\n got %+v\nwant %+v", got, moved)
	}
}
