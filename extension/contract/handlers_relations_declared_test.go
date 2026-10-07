package contract

import (
	"context"
	"strings"
	"testing"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedDocumentType declares `document` at ns for t1: owner takes a user,
// viewer a user or a group's members.
func seedDocumentType(t *testing.T, s *memory.Store, ns string) {
	t.Helper()
	err := s.CreateResourceType(context.Background(), &resourcetype.ResourceType{
		TenantID: "t1", NamespacePath: ns, Name: "document",
		Relations: []resourcetype.RelationDef{
			{Name: "owner", AllowedSubjects: []string{"user"}},
			{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
		},
	})
	if err != nil {
		t.Fatalf("seed resource type: %v", err)
	}
}

func TestRelationsCreateObeysTheGoverningResourceType(t *testing.T) {
	s := memory.New()
	seedDocumentType(t, s, "eng")
	h := relationsCreateHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	written := []struct {
		name string
		in   RelationCreateInput
	}{
		{"undeclared object type", RelationCreateInput{NamespacePath: "eng", ObjectType: "folder", ObjectID: "f", Relation: "anything", SubjectType: "team", SubjectID: "x"}},
		{"declared relation, allowed subject", RelationCreateInput{NamespacePath: "eng", ObjectType: "document", ObjectID: "d1", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}},
		{"allowed subject set", RelationCreateInput{NamespacePath: "eng", ObjectType: "document", ObjectID: "d1", Relation: "viewer", SubjectType: "group", SubjectID: "eng", SubjectRelation: "member"}},
		{"ancestor governs a child namespace", RelationCreateInput{NamespacePath: "eng/platform", ObjectType: "document", ObjectID: "d2", Relation: "owner", SubjectType: "user", SubjectID: "bob"}},
		{"a sibling's declaration does not govern", RelationCreateInput{NamespacePath: "sales", ObjectType: "document", ObjectID: "d3", Relation: "editor", SubjectType: "team", SubjectID: "x"}},
	}
	for _, c := range written {
		if _, err := h(ctx, c.in, principalFor("t1")); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	refused := []struct {
		name string
		in   RelationCreateInput
		msg  string
	}{
		{
			"undeclared relation",
			RelationCreateInput{NamespacePath: "eng", ObjectType: "document", ObjectID: "d1", Relation: "editor", SubjectType: "user", SubjectID: "alice"},
			`tuple document:d1#editor@user:alice in namespace "eng" is refused: resource type "document" in namespace "eng" declares no relation "editor" (its relations are "owner", "viewer")`,
		},
		{
			"disallowed subject",
			RelationCreateInput{NamespacePath: "eng", ObjectType: "document", ObjectID: "d1", Relation: "owner", SubjectType: "group", SubjectID: "eng"},
			`tuple document:d1#owner@group:eng in namespace "eng" is refused: relation "owner" of resource type "document" in namespace "eng" allows subjects "user", not "group"`,
		},
		{
			"ancestor refuses in a child namespace",
			RelationCreateInput{NamespacePath: "eng/platform", ObjectType: "document", ObjectID: "d1", Relation: "viewer", SubjectType: "group", SubjectID: "eng"},
			`tuple document:d1#viewer@group:eng in namespace "eng/platform" is refused: relation "viewer" of resource type "document" in namespace "eng" allows subjects "user", "group#member", not "group"`,
		},
	}
	for _, c := range refused {
		_, err := h(ctx, c.in, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%s: want CodeBadRequest, got %v", c.name, err)
			continue
		}
		if ce.Message != c.msg {
			t.Errorf("%s:\n got %s\nwant %s", c.name, ce.Message, c.msg)
		}
	}

	rows, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != len(written) {
		t.Errorf("stored %d tuples, want %d: a refused tuple was written", len(rows), len(written))
	}
	for _, r := range rows {
		if r.Relation == "editor" && r.NamespacePath == "eng" || strings.HasPrefix(r.SubjectType, "group") && r.SubjectRelation == "" {
			t.Errorf("refused tuple stored: %+v", r)
		}
	}
}
