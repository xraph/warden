package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/memory"
)

// missedReadStore makes the REST delete's read of the matching tuples miss
// them: it returns no rows, or an error, as a read made just before a
// concurrent write (or a failing read) would. The delete itself still
// reaches the memory store and removes the rows.
type missedReadStore struct {
	*memory.Store
	readErr error
}

func (m missedReadStore) ListRelations(context.Context, *relation.ListFilter) ([]*relation.Tuple, error) {
	return nil, m.readErr
}

// relationDeletedProbe records the IDs the typed OnRelationDeleted hook
// receives.
type relationDeletedProbe struct {
	mu  sync.Mutex
	ids []id.RelationID
}

func (p *relationDeletedProbe) Name() string { return "relation-deleted-probe" }

func (p *relationDeletedProbe) OnRelationDeleted(_ context.Context, rid id.RelationID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ids = append(p.ids, rid)
	return nil
}

func (p *relationDeletedProbe) got() []id.RelationID {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]id.RelationID(nil), p.ids...)
}

// newCachedRelationAPI builds the REST API over an engine with a real
// memory cache, so the engine's own cache invalidator is registered.
func newCachedRelationAPI(t *testing.T, wrap ...func(*memory.Store) store.Store) (http.Handler, *warden.Engine, *memory.Store, *warden.MemoryCache, *relationDeletedProbe) {
	t.Helper()
	s := memory.New()
	var engStore store.Store = s
	if len(wrap) > 0 {
		engStore = wrap[0](s)
	}
	c := warden.NewMemoryCache(warden.WithCacheTTL(time.Hour))
	probe := &relationDeletedProbe{}
	eng, err := warden.NewEngine(warden.WithStore(engStore), warden.WithCache(c), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	router := forge.NewRouter()
	a := New(eng, router, WithAuthorizer(allowAllAuthorizer))
	if err := a.RegisterRoutes(router); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	return router.Handler(), eng, s, c, probe
}

func restDelete(t *testing.T, h http.Handler, body map[string]any) {
	t.Helper()
	rec := do(h, request(http.MethodPost, "/v1/relations/delete", "alice", testTenant, body))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRelations_RESTDeleteRevokesACachedAllow(t *testing.T) {
	// A revoke through REST must take effect on the next Check, not when
	// the cached ALLOW ages out an hour later. That must hold whatever the
	// read before the delete saw: the tuple, nothing (a write that landed
	// between the read and the delete), or an error.
	for name, wrap := range map[string]func(*memory.Store) store.Store{
		"read finds the tuple": func(s *memory.Store) store.Store { return s },
		"read finds nothing":   func(s *memory.Store) store.Store { return missedReadStore{Store: s} },
		"read fails": func(s *memory.Store) store.Store {
			return missedReadStore{Store: s, readErr: errors.New("read failed")}
		},
	} {
		t.Run(name, func(t *testing.T) { checkRESTDeleteRevokes(t, wrap) })
	}
}

func checkRESTDeleteRevokes(t *testing.T, wrap func(*memory.Store) store.Store) {
	t.Helper()
	h, eng, s, c, _ := newCachedRelationAPI(t, wrap)
	ctx := warden.WithTenant(context.Background(), testApp, testTenant)
	if err := s.CreateRelation(ctx, &relation.Tuple{
		TenantID: testTenant, ObjectType: "document", ObjectID: "doc1",
		Relation: "read", SubjectType: "user", SubjectID: "bob",
	}); err != nil {
		t.Fatalf("seed tuple: %v", err)
	}
	req := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "bob"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "doc1"},
	}

	res, err := eng.Check(ctx, req)
	if err != nil || !res.Allowed {
		t.Fatalf("check before delete: res=%+v err=%v, want allowed", res, err)
	}
	if cached, ok := c.Get(ctx, testTenant, "", req); !ok || !cached.Allowed {
		t.Fatalf("the allow was not cached (ok=%v, %+v), so this test proves nothing", ok, cached)
	}

	restDelete(t, h, map[string]any{
		"object_type": "document", "object_id": "doc1", "relation": "read",
		"subject_type": "user", "subject_id": "bob",
	})

	if _, ok := c.Get(ctx, testTenant, "", req); ok {
		t.Error("the cached allow survived the REST delete")
	}
	res, err = eng.Check(ctx, req)
	if err != nil {
		t.Fatalf("check after delete: %v", err)
	}
	if res.Allowed {
		t.Error("check after the REST delete still allows")
	}
}

func TestRelations_RESTDeleteFiresTheTypedHookOncePerRemovedTuple(t *testing.T) {
	// The key leaves out subject_relation, so group:eng and group:eng#member
	// both go, and each gets its own OnRelationDeleted with its own ID.
	h, _, s, _, probe := newCachedRelationAPI(t)
	plain := seedRESTTuple(t, s, testTenant, "", "")
	member := seedRESTTuple(t, s, testTenant, "", "member")

	deleteRESTTuple(t, h, "")

	got := probe.got()
	if len(got) != 2 {
		t.Fatalf("OnRelationDeleted fired %d times with %v, want 2", len(got), got)
	}
	want := map[string]bool{plain.ID.String(): true, member.ID.String(): true}
	for _, rid := range got {
		if !want[rid.String()] {
			t.Errorf("OnRelationDeleted got %q, want one of the removed tuples", rid)
		}
		delete(want, rid.String())
	}
	if len(want) != 0 {
		t.Errorf("no OnRelationDeleted for %v", want)
	}
}

func TestRelations_RESTDeleteThatFoundNothingStillClearsTheCache(t *testing.T) {
	// The read and the delete are two calls. When the read finds nothing,
	// the delete may still remove a tuple written in between, and
	// DeleteRelationTuple does not say how many rows it removed. So the
	// handler fires the hook once with the zero ID: a spurious cache clear
	// is safe, a missed one leaves a stale allow.
	h, _, _, _, probe := newCachedRelationAPI(t)

	deleteRESTTuple(t, h, "")

	got := probe.got()
	if len(got) != 1 || !got[0].IsNil() {
		t.Errorf("OnRelationDeleted got %v, want exactly one zero ID", got)
	}
}
