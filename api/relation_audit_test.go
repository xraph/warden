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

// deleteRESTTuple deletes document:doc1#viewer@group:eng in namespace ns,
// with the given subject relation. An empty one is left out of the body,
// as a client naming the direct tuple would.
func deleteRESTTuple(t *testing.T, h http.Handler, ns, subjectRelation string) {
	t.Helper()
	body := map[string]any{
		"namespace_path": ns,
		"object_type":    "document", "object_id": "doc1", "relation": "viewer",
		"subject_type": "group", "subject_id": "eng",
	}
	if subjectRelation != "" {
		body["subject_relation"] = subjectRelation
	}
	rec := do(h, request(http.MethodPost, "/v1/relations/delete", "alice", testTenant, body))
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

	deleteRESTTuple(t, h, "eng", "")

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

func TestRelations_RESTDeleteRemovesAndAuditsOnlyTheTupleItNames(t *testing.T) {
	// The key includes subject_relation. With group:eng and group:eng#member
	// both stored, a delete with no subject relation removes the direct
	// tuple and one with "member" removes the subject set; each leaves the
	// other in place and audits only the tuple it removed.
	for _, tc := range []struct {
		name, subjectRelation string
	}{
		{"direct tuple", ""},
		{"subject set", "member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s, probe := newRelationAuditAPI(t)
			plain := seedRESTTuple(t, s, testTenant, "", "")
			member := seedRESTTuple(t, s, testTenant, "", "member")
			removed, left := plain, member
			if tc.subjectRelation != "" {
				removed, left = member, plain
			}

			deleteRESTTuple(t, h, "", tc.subjectRelation)

			rows, err := s.ListRelations(context.Background(), &relation.ListFilter{TenantID: testTenant})
			if err != nil || len(rows) != 1 || rows[0].ID != left.ID {
				t.Fatalf("rows left = %+v, err %v; want only %s", rows, err, left.ID)
			}
			got := probe.deleted()
			if len(got) != 1 {
				t.Fatalf("relation.deleted events = %d, want 1: %+v", len(got), got)
			}
			if got[0].EntityID != removed.ID.String() {
				t.Errorf("event names %q, want the removed tuple %s", got[0].EntityID, removed.ID)
			}
			if b, ok := got[0].Before.(*relation.Tuple); !ok || !reflect.DeepEqual(b, removed) {
				t.Errorf("before = %#v, want %#v", got[0].Before, removed)
			}
			if got[0].Entity != nil {
				t.Errorf("entity = %#v, want nil", got[0].Entity)
			}
		})
	}
}

func TestRelations_RESTDeleteOfTheDirectTupleLeavesTheSubjectSetUnaudited(t *testing.T) {
	// Only group:eng#member is stored. A delete of group:eng names no
	// stored tuple, so it removes nothing and audits nothing, even though
	// a read with an empty subject relation filter (which means any) would
	// return the subject set.
	h, s, probe := newRelationAuditAPI(t)
	member := seedRESTTuple(t, s, testTenant, "", "member")

	deleteRESTTuple(t, h, "", "")

	if _, err := s.GetRelation(context.Background(), testTenant, member.ID); err != nil {
		t.Errorf("group:eng#member was removed by a delete of group:eng: %v", err)
	}
	if got := probe.deleted(); len(got) != 0 {
		t.Errorf("relation.deleted events = %+v, want none (nothing was removed)", got)
	}
}

func TestRelations_RESTDeleteOfNothingAuditsNothing(t *testing.T) {
	h, _, probe := newRelationAuditAPI(t)
	deleteRESTTuple(t, h, "", "")
	if got := probe.deleted(); len(got) != 0 {
		t.Errorf("relation.deleted events = %+v, want none (nothing was removed)", got)
	}
}

func TestRelations_RESTDeleteWhoseReadFailedAuditsTheWholeKey(t *testing.T) {
	// With no tuple to name, the one event names the key the delete
	// covered: the namespace, and the subject relation, which is part of
	// the key. The direct tuple with the same fields is not removed.
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
	plain := seedRESTTuple(t, s, testTenant, "eng", "")
	seedRESTTuple(t, s, testTenant, "eng", "member")

	deleteRESTTuple(t, router.Handler(), "eng", "member")

	got := probe.deleted()
	want := "namespace eng: document:doc1#viewer@group:eng#member"
	if len(got) != 1 || got[0].EntityID != want || got[0].TenantID != testTenant {
		t.Fatalf("relation.deleted events = %+v, want one with EntityID %q", got, want)
	}
	if got[0].Entity != nil || got[0].Before != nil {
		t.Errorf("entity %#v, before %#v; want both nil (the read named no tuple)", got[0].Entity, got[0].Before)
	}
	if rows, _ := s.ListRelations(context.Background(), &relation.ListFilter{TenantID: testTenant}); len(rows) != 1 || rows[0].ID != plain.ID {
		t.Errorf("rows left = %+v, want only the direct tuple %s", rows, plain.ID)
	}
}

func TestRelations_RESTDeleteKeyNamesTheTenantRoot(t *testing.T) {
	got := relationDeleteKey(&DeleteRelationRequest{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer", SubjectType: "user", SubjectID: "bob",
	})
	if want := "tenant root: document:doc1#viewer@user:bob (no subject relation)"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}

func TestRelations_RESTDeleteKeyNamesTheSubjectRelation(t *testing.T) {
	got := relationDeleteKey(&DeleteRelationRequest{
		NamespacePath: "eng",
		ObjectType:    "document", ObjectID: "doc1", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: "member",
	})
	if want := "namespace eng: document:doc1#viewer@group:eng#member"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}
