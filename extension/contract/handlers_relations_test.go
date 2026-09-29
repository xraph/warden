package contract

import (
	"context"
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

func TestRelationsListDoesNotCascadeAcrossNamespaces(t *testing.T) {
	// Roles, permissions, policies and resource types resolve up the
	// ancestor chain. Tuples deliberately do not, because they name
	// concrete object and subject pairs and cross-namespace matching would
	// be semantically wrong (see relation/relation.go's type comment).
	// A list that cascaded would imply access the engine will not grant.
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

	if _, err := relationsDeleteHandler(deps)(ctx, RelationDeleteInput{ID: ack.ID}, principalFor("t1")); err != nil {
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

func TestRelationsDeleteRefusesAMalformedID(t *testing.T) {
	h := relationsDeleteHandler(Deps{Engine: engineOver(t, memory.New())})
	_, err := h(context.Background(), RelationDeleteInput{ID: "not-an-id"}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}

func TestRelationsListDoesNotIncludeDescendantNamespaces(t *testing.T) {
	// The other direction of the no-cascade rule: filtering on "eng" must not
	// sweep in "eng/platform" the way a prefix match would.
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
