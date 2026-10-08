package contract

import (
	"context"
	"reflect"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func seedTuple(t *testing.T, s *memory.Store, namespace, objType, objID, rel, subjType, subjID string) *relation.Tuple {
	t.Helper()
	tp := &relation.Tuple{
		TenantID:      "t1",
		NamespacePath: namespace,
		ObjectType:    objType,
		ObjectID:      objID,
		Relation:      rel,
		SubjectType:   subjType,
		SubjectID:     subjID,
	}
	if err := s.CreateRelation(context.Background(), tp); err != nil {
		t.Fatalf("create tuple: %v", err)
	}
	return tp
}

func TestRelationsListPagesFiltersAndCounts(t *testing.T) {
	s := memory.New()
	seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")
	seedTuple(t, s, "", "document", "readme", "editor", "user", "bob")
	seedTuple(t, s, "", "folder", "root", "parent", "document", "readme")
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})

	all, err := h(context.Background(), RelationsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.list: %v", err)
	}
	if all.Total != 3 {
		t.Errorf("total = %d, want 3", all.Total)
	}

	byObject, err := h(context.Background(), RelationsListInput{ObjectType: "document"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("filtered: %v", err)
	}
	if byObject.Total != 2 {
		t.Errorf("objectType=document total = %d, want 2", byObject.Total)
	}
	for _, r := range byObject.Items {
		if r.ObjectType != "document" {
			t.Errorf("object filter leaked %q", r.ObjectType)
		}
	}
}

func TestRelationsListIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	seedTuple(t, s, "", "document", "mine", "viewer", "user", "alice")
	other := &relation.Tuple{
		TenantID: "t2", ObjectType: "document", ObjectID: "theirs",
		Relation: "viewer", SubjectType: "user", SubjectID: "bob",
	}
	if err := s.CreateRelation(ctx, other); err != nil {
		t.Fatalf("create other tenant's tuple: %v", err)
	}
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, RelationsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.list: %v", err)
	}
	for _, r := range got.Items {
		if r.ObjectID == "theirs" {
			t.Fatal("t1 can see t2's tuple: tenant scoping is not applied")
		}
	}
	if got.Total != 1 {
		t.Errorf("total = %d, want 1", got.Total)
	}
}

func TestRelationsCreateWritesTheTuple(t *testing.T) {
	s := memory.New()
	h := relationsCreateHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), RelationCreateInput{
		ObjectType: "document", ObjectID: "readme",
		Relation: "viewer", SubjectType: "user", SubjectID: "alice",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.create: %v", err)
	}
	if got.ID == "" {
		t.Fatal("create returned no id")
	}
}

func TestRelationsCreateRequiresEveryPartOfTheTriple(t *testing.T) {
	// A tuple missing any part matches nothing and is unreachable by every
	// filter, so it is silent junk rather than a partial grant.
	s := memory.New()
	h := relationsCreateHandler(Deps{Engine: engineOver(t, s)})
	full := RelationCreateInput{
		ObjectType: "document", ObjectID: "readme",
		Relation: "viewer", SubjectType: "user", SubjectID: "alice",
	}

	for _, missing := range []string{"objectType", "objectId", "relation", "subjectType", "subjectId"} {
		in := full
		switch missing {
		case "objectType":
			in.ObjectType = ""
		case "objectId":
			in.ObjectID = ""
		case "relation":
			in.Relation = ""
		case "subjectType":
			in.SubjectType = ""
		case "subjectId":
			in.SubjectID = ""
		}
		_, err := h(context.Background(), in, principalFor("t1"))
		if err == nil {
			t.Errorf("want a refusal with %s missing", missing)
			continue
		}
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%s missing: want CodeBadRequest, got %v", missing, err)
		}
	}
}

func TestRelationsCreateRefusesADuplicateTuple(t *testing.T) {
	s := memory.New()
	seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")
	h := relationsCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), RelationCreateInput{
		ObjectType: "document", ObjectID: "readme",
		Relation: "viewer", SubjectType: "user", SubjectID: "alice",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal for a duplicate tuple")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Errorf("want CodeConflict, got %v", err)
	}
}

func TestRelationsDeleteRemovesTheTuple(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	tp := seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")
	h := relationsDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, RelationDeleteInput{ID: tp.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("relations.delete: %v", err)
	}
	rows, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
}

func TestRelationsDeleteOfAnotherTenantsTupleIsNotFound(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	other := &relation.Tuple{
		TenantID: "t2", ObjectType: "document", ObjectID: "theirs",
		Relation: "viewer", SubjectType: "user", SubjectID: "bob",
	}
	if err := s.CreateRelation(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := relationsDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, RelationDeleteInput{ID: other.ID.String()}, principalFor("t1"))
	if err == nil {
		t.Fatal("want NOT_FOUND deleting another tenant's tuple")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Errorf("want CodeNotFound, got %v", err)
	}
}

func TestRelationsListFilterIsExactMatchAndOmitsAncestorTuples(t *testing.T) {
	// This pins the LIST filter, not the check. At check time a tuple at the
	// root DOES apply in eng, because tuples cascade down like roles and
	// policies (TestReBAC_NamespaceCascade). The list filter is an exact
	// match on purpose: filtering on eng shows what is stored at eng, so the
	// root tuple is absent from the listing even though it is in effect.
	s := memory.New()
	seedTuple(t, s, "", "document", "root-doc", "viewer", "user", "alice")
	seedTuple(t, s, "eng", "document", "eng-doc", "viewer", "user", "alice")
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})

	eng := "eng"
	got, err := h(context.Background(), RelationsListInput{NamespacePath: &eng}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.list: %v", err)
	}
	if got.Total != 1 || got.Items[0].ObjectID != "eng-doc" {
		t.Errorf("namespace eng returned %+v, want only eng-doc and no ancestor row", got.Items)
	}
}

// relationProbe adds the two relation hooks to auditProbe.
type relationProbe struct{ *auditProbe }

func (r relationProbe) OnRelationWritten(context.Context, *relation.Tuple) error {
	r.note("relation.written")
	return nil
}

func (r relationProbe) OnRelationDeleted(context.Context, id.RelationID) error {
	r.note("relation.deleted")
	return nil
}

func TestRelationsWritesEmitAuditAndTheTypedHooks(t *testing.T) {
	// Both the typed hook and the audit event drive the cache invalidator. A
	// tuple deleted without them leaves a cached ALLOW for a subject who no
	// longer has the relation.
	s := memory.New()
	probe := relationProbe{&auditProbe{}}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	deps := Deps{Engine: eng}
	ctx := context.Background()

	ack, err := relationsCreateHandler(deps)(ctx, RelationCreateInput{
		ObjectType: "document", ObjectID: "readme",
		Relation: "viewer", SubjectType: "user", SubjectID: "alice",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.create: %v", err)
	}
	created := probe.event(t, "relation.written")
	if created.Actor != wantActor || created.TenantID != "t1" || created.EntityID != ack.ID {
		t.Errorf("create event = %+v", created)
	}
	if !probe.hasTyped("relation.written") {
		t.Error("the typed OnRelationWritten hook did not fire")
	}
	if probe.ctxActor != wantActor {
		t.Errorf("the context reaching the create hooks carries actor %+v, want %+v", probe.ctxActor, wantActor)
	}
	rows, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("stored rows = %v, err %v", rows, err)
	}
	if rows[0].CreatedBy != "tester" {
		t.Errorf("createdBy = %q, want tester", rows[0].CreatedBy)
	}

	if _, err := relationsDeleteHandler(deps)(ctx, RelationDeleteInput(ack), principalFor("t1")); err != nil {
		t.Fatalf("relations.delete: %v", err)
	}
	del := probe.event(t, "relation.deleted")
	if del.EntityID != ack.ID || del.TenantID != "t1" || del.Actor != wantActor {
		t.Errorf("delete event = %+v", del)
	}
	if !probe.hasTyped("relation.deleted") {
		t.Error("the typed OnRelationDeleted hook did not fire")
	}
	if probe.ctxActor != wantActor {
		t.Errorf("the context reaching the delete hooks carries actor %+v, want %+v", probe.ctxActor, wantActor)
	}
}

func TestRelationsDeleteAuditsTheWholeTuple(t *testing.T) {
	// An audit row that says only "relation <id> deleted" cannot be read
	// back once the row is gone. The event must carry the tuple itself as
	// the before entity, the same shape policy and role deletes use.
	s := memory.New()
	probe := relationProbe{&auditProbe{}}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	ctx := context.Background()
	tp := &relation.Tuple{
		TenantID: "t1", NamespacePath: "eng",
		ObjectType: "document", ObjectID: "readme", Relation: "viewer",
		SubjectType: "group", SubjectID: "engineering", SubjectRelation: "member",
		CreatedBy: "seeder",
	}
	if err := s.CreateRelation(ctx, tp); err != nil {
		t.Fatalf("create tuple: %v", err)
	}
	stored, err := s.GetRelation(ctx, "t1", tp.ID)
	if err != nil {
		t.Fatalf("get tuple: %v", err)
	}

	if _, err := relationsDeleteHandler(Deps{Engine: eng})(ctx, RelationDeleteInput{ID: tp.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("relations.delete: %v", err)
	}
	del := probe.event(t, "relation.deleted")
	if del.EntityID != tp.ID.String() || del.TenantID != "t1" {
		t.Errorf("delete event = %+v", del)
	}
	if del.Entity != nil {
		t.Errorf("delete entity = %#v, want nil (the tuple no longer exists)", del.Entity)
	}
	if b, ok := del.Before.(*relation.Tuple); !ok || !reflect.DeepEqual(b, stored) {
		t.Errorf("delete before = %#v, want the stored tuple %#v", del.Before, stored)
	}
}

func TestRelationsDeleteOfAForeignOrMissingIDAuditsNothing(t *testing.T) {
	s := memory.New()
	probe := relationProbe{&auditProbe{}}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	ctx := context.Background()
	theirs := &relation.Tuple{
		TenantID: "t2", ObjectType: "document", ObjectID: "theirs",
		Relation: "viewer", SubjectType: "user", SubjectID: "bob",
	}
	if err := s.CreateRelation(ctx, theirs); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := relationsDeleteHandler(Deps{Engine: eng})

	for name, rid := range map[string]string{
		"foreign": theirs.ID.String(),
		"missing": id.NewRelationID().String(),
	} {
		_, err := h(ctx, RelationDeleteInput{ID: rid}, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
			t.Errorf("%s id: want CodeNotFound, got %v", name, err)
		}
	}
	probe.mu.Lock()
	events, typed := len(probe.events), len(probe.typed)
	probe.mu.Unlock()
	if events != 0 || typed != 0 {
		t.Errorf("a refused delete emitted %d audit events and %d typed hooks, want none", events, typed)
	}
	if _, err := s.GetRelation(ctx, "t2", theirs.ID); err != nil {
		t.Errorf("t2's tuple is gone after t1's refused delete: %v", err)
	}
}

func TestRelationsDeleteRefusesAMalformedID(t *testing.T) {
	h := relationsDeleteHandler(Deps{Engine: engineOver(t, memory.New())})
	_, err := h(context.Background(), RelationDeleteInput{ID: "not-an-id"}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}

func TestRelationsListDoesNotIncludeDescendantNamespaces(t *testing.T) {
	// The other direction of the exact-match list filter: filtering on "eng"
	// must not sweep in "eng/platform" the way a prefix match would. This is
	// about the listing only; see the test above for how checks differ.
	s := memory.New()
	seedTuple(t, s, "eng", "document", "eng-doc", "viewer", "user", "alice")
	seedTuple(t, s, "eng/platform", "document", "platform-doc", "viewer", "user", "alice")
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})

	eng := "eng"
	got, err := h(context.Background(), RelationsListInput{NamespacePath: &eng}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.list: %v", err)
	}
	if got.Total != 1 || got.Items[0].ObjectID != "eng-doc" {
		t.Errorf("namespace eng returned %+v, want only eng-doc and no descendant row", got.Items)
	}
}

func TestRelationsListReturnsRealPages(t *testing.T) {
	// Five rows, pages of two. Total is the full filtered count on every
	// page, the pages are disjoint, and together they cover every row.
	s := memory.New()
	for _, oid := range []string{"a", "b", "c", "d", "e"} {
		seedTuple(t, s, "", "document", oid, "viewer", "user", "alice")
	}
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	seen := map[string]struct{}{}
	for _, page := range []struct{ offset, wantLen int }{{0, 2}, {2, 2}, {4, 1}} {
		got, err := h(ctx, RelationsListInput{PageRequest: PageRequest{Limit: 2, Offset: page.offset}}, principalFor("t1"))
		if err != nil {
			t.Fatalf("offset %d: %v", page.offset, err)
		}
		if len(got.Items) != page.wantLen {
			t.Errorf("offset %d: %d items, want %d", page.offset, len(got.Items), page.wantLen)
		}
		if got.Total != 5 {
			t.Errorf("offset %d: total = %d, want 5 on every page", page.offset, got.Total)
		}
		if got.Limit != 2 || got.Offset != page.offset {
			t.Errorf("offset %d: echoed limit/offset = %d/%d", page.offset, got.Limit, got.Offset)
		}
		for _, r := range got.Items {
			if _, dup := seen[r.ObjectID]; dup {
				t.Errorf("offset %d: %q appeared on an earlier page", page.offset, r.ObjectID)
			}
			seen[r.ObjectID] = struct{}{}
		}
	}
	if len(seen) != 5 {
		t.Errorf("pages covered %d distinct rows, want 5", len(seen))
	}

	past, err := h(ctx, RelationsListInput{PageRequest: PageRequest{Limit: 2, Offset: 10}}, principalFor("t1"))
	if err != nil {
		t.Fatalf("past the end: %v", err)
	}
	if len(past.Items) != 0 || past.Total != 5 {
		t.Errorf("past the end: %d items, total %d, want 0 and 5", len(past.Items), past.Total)
	}
}

func TestRelationsListFiltersOnEveryField(t *testing.T) {
	// Each filter must narrow both the items and Total. A Total computed
	// from a different filter than the items would make every pager wrong.
	s := memory.New()
	seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")  // 1
	seedTuple(t, s, "", "document", "readme", "editor", "user", "bob")    // 2
	seedTuple(t, s, "", "document", "spec", "viewer", "user", "alice")    // 3
	seedTuple(t, s, "", "folder", "root", "parent", "document", "readme") // 4
	seedTuple(t, s, "", "group", "eng", "member", "user", "alice")        // 5
	// seedTuple has no subject-relation parameter, so row 6 is written directly.
	userset := &relation.Tuple{
		TenantID: "t1", ObjectType: "group", ObjectID: "eng", Relation: "member",
		SubjectType: "group", SubjectID: "ops", SubjectRelation: "member",
	}
	if err := s.CreateRelation(context.Background(), userset); err != nil { // 6
		t.Fatalf("create the userset tuple: %v", err)
	}
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})

	cases := []struct {
		name  string
		in    RelationsListInput
		total int64
		match func(RelationSummary) bool
	}{
		{"objectType", RelationsListInput{ObjectType: "document"}, 3, func(r RelationSummary) bool { return r.ObjectType == "document" }},
		{"objectId", RelationsListInput{ObjectID: "readme"}, 2, func(r RelationSummary) bool { return r.ObjectID == "readme" }},
		{"relation", RelationsListInput{Relation: "viewer"}, 2, func(r RelationSummary) bool { return r.Relation == "viewer" }},
		{"subjectType", RelationsListInput{SubjectType: "user"}, 4, func(r RelationSummary) bool { return r.SubjectType == "user" }},
		{"subjectId", RelationsListInput{SubjectID: "alice"}, 3, func(r RelationSummary) bool { return r.SubjectID == "alice" }},
		{"subjectRelation", RelationsListInput{SubjectRelation: "member"}, 1, func(r RelationSummary) bool { return r.SubjectRelation == "member" }},
		{"objectType and subjectId", RelationsListInput{ObjectType: "document", SubjectID: "alice"}, 2, func(r RelationSummary) bool {
			return r.ObjectType == "document" && r.SubjectID == "alice"
		}},
	}
	for _, tc := range cases {
		got, err := h(context.Background(), tc.in, principalFor("t1"))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Total != tc.total || int64(len(got.Items)) != tc.total {
			t.Errorf("%s: total %d with %d items, want %d of each", tc.name, got.Total, len(got.Items), tc.total)
		}
		for _, r := range got.Items {
			if !tc.match(r) {
				t.Errorf("%s: filter leaked %+v", tc.name, r)
			}
		}
	}

	// A filter and a page together: Total is the filtered count, not the
	// size of the page.
	paged, err := h(context.Background(), RelationsListInput{
		PageRequest: PageRequest{Limit: 1}, ObjectType: "document", SubjectID: "alice",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("filter with paging: %v", err)
	}
	if len(paged.Items) != 1 || paged.Total != 2 {
		t.Errorf("filter with paging: %d items, total %d, want 1 and 2", len(paged.Items), paged.Total)
	}
}

func TestRelationsCreateStoresEveryFieldItWasGiven(t *testing.T) {
	// Read the row back. An ack with an id proves nothing about what landed.
	// Task 3's resource type delete guard finds tuples by namespace, so a
	// namespace silently dropped here would surface far from its cause.
	s := memory.New()
	ctx := context.Background()
	h := relationsCreateHandler(Deps{Engine: engineOver(t, s)})

	ack, err := h(ctx, RelationCreateInput{
		NamespacePath: "eng/platform",
		ObjectType:    "document", ObjectID: "readme",
		Relation: "viewer", SubjectType: "group", SubjectID: "ops", SubjectRelation: "member",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.create: %v", err)
	}
	rows, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("stored rows = %v, err %v", rows, err)
	}
	got := rows[0]
	want := relation.Tuple{
		TenantID: "t1", NamespacePath: "eng/platform",
		ObjectType: "document", ObjectID: "readme", Relation: "viewer",
		SubjectType: "group", SubjectID: "ops", SubjectRelation: "member",
		CreatedBy: "tester",
	}
	if got.ID.String() != ack.ID || got.TenantID != want.TenantID || got.NamespacePath != want.NamespacePath ||
		got.ObjectType != want.ObjectType || got.ObjectID != want.ObjectID || got.Relation != want.Relation ||
		got.SubjectType != want.SubjectType || got.SubjectID != want.SubjectID ||
		got.SubjectRelation != want.SubjectRelation || got.CreatedBy != want.CreatedBy {
		t.Errorf("stored %+v (ack %q), want %+v", got, ack.ID, want)
	}

	// The same tuple in the tenant root is a different tuple, not a duplicate.
	if _, err := h(ctx, RelationCreateInput{
		ObjectType: "document", ObjectID: "readme",
		Relation: "viewer", SubjectType: "group", SubjectID: "ops", SubjectRelation: "member",
	}, principalFor("t1")); err != nil {
		t.Errorf("same triple at the tenant root should be allowed: %v", err)
	}
}

func TestRelationsCreateRefusesAnInvalidNamespace(t *testing.T) {
	s := memory.New()
	h := relationsCreateHandler(Deps{Engine: engineOver(t, s)})
	for _, ns := range []string{"/eng", "eng/", "eng//platform", "Eng Platform"} {
		_, err := h(context.Background(), RelationCreateInput{
			NamespacePath: ns,
			ObjectType:    "document", ObjectID: "readme",
			Relation: "viewer", SubjectType: "user", SubjectID: "alice",
		}, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("namespace %q: want CodeBadRequest, got %v", ns, err)
		}
	}
	rows, _ := s.ListRelations(context.Background(), &relation.ListFilter{TenantID: "t1"})
	if len(rows) != 0 {
		t.Errorf("a refused create stored %d rows", len(rows))
	}
}
