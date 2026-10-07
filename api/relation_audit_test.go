package api

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store/memory"
)

// relationAuditProbe records every audit event.
type relationAuditProbe struct {
	mu     sync.Mutex
	events []plugin.Event
}

func (p *relationAuditProbe) Name() string { return "relation-audit-probe" }

func (p *relationAuditProbe) OnAudit(_ context.Context, ev plugin.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
	return nil
}

func (p *relationAuditProbe) deleted() []plugin.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []plugin.Event
	for _, ev := range p.events {
		if ev.Action == "relation.deleted" {
			out = append(out, ev)
		}
	}
	return out
}

// newRelationAuditAPI is newTestAPI with the store exposed for seeding and
// an audit probe installed on the engine.
func newRelationAuditAPI(t *testing.T) (http.Handler, *memory.Store, *relationAuditProbe) {
	t.Helper()
	s := memory.New()
	probe := &relationAuditProbe{}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	router := forge.NewRouter()
	a := New(eng, router, WithAuthorizer(allowAllAuthorizer))
	if err := a.RegisterRoutes(router); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	return router.Handler(), s, probe
}

func seedRESTTuple(t *testing.T, s *memory.Store, tenant, ns, subjectRelation string) *relation.Tuple {
	t.Helper()
	tp := &relation.Tuple{
		TenantID: tenant, NamespacePath: ns,
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: subjectRelation,
	}
	if err := s.CreateRelation(context.Background(), tp); err != nil {
		t.Fatalf("seed tuple: %v", err)
	}
	stored, err := s.GetRelation(context.Background(), tenant, tp.ID)
	if err != nil {
		t.Fatalf("read seeded tuple: %v", err)
	}
	return stored
}

func deleteRESTTuple(t *testing.T, h http.Handler, ns string) {
	t.Helper()
	rec := do(h, request(http.MethodPost, "/v1/relations/delete", "alice", testTenant, map[string]any{
		"namespace_path": ns,
		"object_type":    "document", "object_id": "doc1", "relation": "viewer",
		"subject_type": "group", "subject_id": "eng",
	}))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRelations_RESTDeleteAuditsTheRemovedTupleByID(t *testing.T) {
	// The same shape as the dashboard's relations.delete: EntityID is the
	// tuple's ID, so the event links to its relation.written; Before is the
	// tuple, namespace included; Entity is nil because nothing is left.
	h, s, probe := newRelationAuditAPI(t)
	tp := seedRESTTuple(t, s, testTenant, "eng", "")
	// Same key in another namespace and in another tenant: neither is
	// removed or audited.
	seedRESTTuple(t, s, testTenant, "", "")
	seedRESTTuple(t, s, otherTenant, "eng", "")

	deleteRESTTuple(t, h, "eng")

	got := probe.deleted()
	if len(got) != 1 {
		t.Fatalf("relation.deleted events = %d, want 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.EntityID != tp.ID.String() || ev.TenantID != testTenant {
		t.Errorf("event = %+v, want EntityID %s in %s", ev, tp.ID, testTenant)
	}
	if ev.Entity != nil {
		t.Errorf("entity = %#v, want nil", ev.Entity)
	}
	before, ok := ev.Before.(*relation.Tuple)
	if !ok || !reflect.DeepEqual(before, tp) {
		t.Errorf("before = %#v, want the stored tuple %#v", ev.Before, tp)
	}
	if ok && before.NamespacePath != "eng" {
		t.Errorf("before namespace = %q, want eng", before.NamespacePath)
	}
}

func TestRelations_RESTDeleteAuditsEveryTupleItRemoves(t *testing.T) {
	// The delete key leaves out subject_relation, so one call removes the
	// group:eng row and the group:eng#member row. Each gets its own event.
	h, s, probe := newRelationAuditAPI(t)
	plain := seedRESTTuple(t, s, testTenant, "", "")
	member := seedRESTTuple(t, s, testTenant, "", "member")

	deleteRESTTuple(t, h, "")

	rows, err := s.ListRelations(context.Background(), &relation.ListFilter{TenantID: testTenant})
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows left = %v, err %v; want none", rows, err)
	}
	got := probe.deleted()
	if len(got) != 2 {
		t.Fatalf("relation.deleted events = %d, want 2: %+v", len(got), got)
	}
	want := map[string]*relation.Tuple{plain.ID.String(): plain, member.ID.String(): member}
	for _, ev := range got {
		w, ok := want[ev.EntityID]
		if !ok {
			t.Errorf("event for unexpected entity %q", ev.EntityID)
			continue
		}
		delete(want, ev.EntityID)
		if b, ok := ev.Before.(*relation.Tuple); !ok || !reflect.DeepEqual(b, w) {
			t.Errorf("before for %s = %#v, want %#v", ev.EntityID, ev.Before, w)
		}
		if ev.Entity != nil {
			t.Errorf("entity for %s = %#v, want nil", ev.EntityID, ev.Entity)
		}
	}
	if len(want) != 0 {
		t.Errorf("no event for %v", want)
	}
}

func TestRelations_RESTDeleteOfNothingAuditsNothing(t *testing.T) {
	h, _, probe := newRelationAuditAPI(t)
	deleteRESTTuple(t, h, "")
	if got := probe.deleted(); len(got) != 0 {
		t.Errorf("relation.deleted events = %+v, want none (nothing was removed)", got)
	}
}

func TestRelations_RESTDeleteWhoseReadFailedAuditsTheWholeKey(t *testing.T) {
	// With no tuple to name, the one event names what the delete covered:
	// the namespace, and every subject relation, since the key leaves it
	// out.
	s := memory.New()
	probe := &relationAuditProbe{}
	eng, err := warden.NewEngine(
		warden.WithStore(missedReadStore{Store: s, readErr: errors.New("read failed")}),
		warden.WithPlugin(probe),
	)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	router := forge.NewRouter()
	a := New(eng, router, WithAuthorizer(allowAllAuthorizer))
	if err := a.RegisterRoutes(router); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	seedRESTTuple(t, s, testTenant, "eng", "member")

	deleteRESTTuple(t, router.Handler(), "eng")

	got := probe.deleted()
	want := "namespace eng: document:doc1#viewer@group:eng (any subject relation)"
	if len(got) != 1 || got[0].EntityID != want || got[0].TenantID != testTenant {
		t.Fatalf("relation.deleted events = %+v, want one with EntityID %q", got, want)
	}
	if got[0].Entity != nil || got[0].Before != nil {
		t.Errorf("entity %#v, before %#v; want both nil (the read named no tuple)", got[0].Entity, got[0].Before)
	}
	if rows, _ := s.ListRelations(context.Background(), &relation.ListFilter{TenantID: testTenant}); len(rows) != 0 {
		t.Errorf("rows left = %+v, want the tuple deleted", rows)
	}
}

func TestRelations_RESTDeleteKeyNamesTheTenantRoot(t *testing.T) {
	got := relationDeleteKey(&DeleteRelationRequest{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer", SubjectType: "user", SubjectID: "bob",
	})
	if want := "tenant root: document:doc1#viewer@user:bob (any subject relation)"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}
