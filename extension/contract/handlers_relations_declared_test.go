package contract

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/xraph/warden"
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

// countingTypes counts the resource type reads the list makes, by
// namespace and name.
type countingTypes struct {
	*memory.Store
	reads map[string]int
}

func (c *countingTypes) GetResourceTypeByName(ctx context.Context, tenantID, ns, name string) (*resourcetype.ResourceType, error) {
	c.reads[ns+"|"+name]++
	return c.Store.GetResourceTypeByName(ctx, tenantID, ns, name)
}

// seedMarkedTuples writes, straight into the store as a tuple from before
// the write check would be, one conforming tuple and two that eng's
// document type does not declare, beside tuples nothing governs.
func seedMarkedTuples(t *testing.T, s *memory.Store) {
	t.Helper()
	ctx := context.Background()
	seed := []relation.Tuple{
		{ObjectType: "document", ObjectID: "ok", Relation: "viewer", SubjectType: "user", SubjectID: "alice", NamespacePath: "eng"},
		{ObjectType: "document", ObjectID: "old", Relation: "editor", SubjectType: "user", SubjectID: "alice", NamespacePath: "eng"},
		{ObjectType: "document", ObjectID: "child", Relation: "viewer", SubjectType: "group", SubjectID: "eng", NamespacePath: "eng/platform"},
		{ObjectType: "document", ObjectID: "child2", Relation: "owner", SubjectType: "user", SubjectID: "bob", NamespacePath: "eng/platform"},
		// eng's declaration does not govern the root: nothing governs this one.
		{ObjectType: "document", ObjectID: "root", Relation: "editor", SubjectType: "team", SubjectID: "x"},
		{ObjectType: "folder", ObjectID: "f", Relation: "anything", SubjectType: "team", SubjectID: "x", NamespacePath: "eng"},
	}
	for i := range seed {
		tp := seed[i]
		tp.TenantID = "t1"
		if err := s.CreateRelation(ctx, &tp); err != nil {
			t.Fatalf("seed %s: %v", tp.ObjectID, err)
		}
	}
}

func TestRelationsListMarksTuplesThatBreakTheirResourceType(t *testing.T) {
	s := memory.New()
	seedDocumentType(t, s, "eng")
	ctx := context.Background()
	// The list must judge what is stored, not trust it.
	seedMarkedTuples(t, s)
	grantUser(t, s, "tester", "warden:relation:read", "warden:resourcetype:read")
	counting := &countingTypes{Store: s, reads: map[string]int{}}
	eng, err := warden.NewEngine(warden.WithStore(counting))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	h := relationsListHandler(Deps{Engine: eng})

	out, err := h(ctx, RelationsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := map[string]string{
		"ok":     "",
		"old":    `resource type "document" in namespace "eng" declares no relation "editor" (its relations are "owner", "viewer")`,
		"child":  `relation "viewer" of resource type "document" in namespace "eng" allows subjects "user", "group#member", not "group"`,
		"child2": "",
		"root":   "",
		"f":      "",
	}
	if out.MarksWithheld {
		t.Error("marks withheld from a caller who may read resource types")
	}
	if len(out.Items) != len(want) {
		t.Fatalf("listed %d tuples, want %d", len(out.Items), len(want))
	}
	for _, it := range out.Items {
		if it.Undeclared != want[it.ObjectID] {
			t.Errorf("%s:\n got %q\nwant %q", it.ObjectID, it.Undeclared, want[it.ObjectID])
		}
	}
	// Each resource type lookup is made once for the page, however many
	// rows and chains share it: "eng|document" is on the chain of two
	// tuples in eng and two in eng/platform, and is read once.
	for key, n := range counting.reads {
		if n != 1 {
			t.Errorf("read %s %d times, want once", key, n)
		}
	}
	if len(counting.reads) == 0 {
		t.Error("no resource type was read")
	}
}

func TestRelationsListMarkIsOmittedWhenTheTupleConforms(t *testing.T) {
	// omitempty: an older page and a newer one agree that no field means
	// no mark.
	b, err := json.Marshal(RelationSummary{ID: "rel_x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "undeclared") {
		t.Errorf("conforming tuple serialised the mark: %s", b)
	}
}

func TestRelationsListWithholdsMarksFromACallerWhoCannotReadResourceTypes(t *testing.T) {
	// A reason names the governing type's relations or allowed subjects,
	// which resourceTypes.* keeps behind read on warden:resourcetype. A
	// relation reader alone gets the rows, no reasons, and a flag that
	// says the rows were not checked, so no mark cannot read as "conforms".
	s := memory.New()
	seedDocumentType(t, s, "eng")
	seedMarkedTuples(t, s)
	grantUser(t, s, "tester", "warden:relation:read")
	h := relationsListHandler(Deps{Engine: engineOver(t, s)})

	out, err := h(context.Background(), RelationsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !out.MarksWithheld {
		t.Error("marksWithheld = false for a caller without read on warden:resourcetype")
	}
	if len(out.Items) != 6 {
		t.Errorf("listed %d tuples, want 6: withholding marks must not withhold rows", len(out.Items))
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, secret := range []string{"undeclared", "its relations are", "allows subjects"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the JSON reveals %q: %s", secret, raw)
		}
	}
	if !strings.Contains(raw, `"marksWithheld":true`) {
		t.Errorf("the JSON lacks marksWithheld: %s", raw)
	}
}

// brokenTypes answers relation reads normally and fails every resource
// type read with an error that is not a not-found.
type brokenTypes struct {
	*memory.Store
}

func (brokenTypes) GetResourceTypeByName(context.Context, string, string, string) (*resourcetype.ResourceType, error) {
	return nil, errors.New("resource types unreadable")
}

func TestRelationsListFailsWhenTheSchemaCannotBeRead(t *testing.T) {
	// An unmarked row would claim a check that never ran, so a schema read
	// error fails the list rather than returning rows without marks.
	s := memory.New()
	seedDocumentType(t, s, "eng")
	seedMarkedTuples(t, s)
	grantUser(t, s, "tester", "warden:relation:read", "warden:resourcetype:read")
	eng, err := warden.NewEngine(warden.WithStore(brokenTypes{s}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	out, err := relationsListHandler(Deps{Engine: eng})(context.Background(), RelationsListInput{}, principalFor("t1"))
	if err == nil {
		t.Fatalf("list succeeded with %d items, want an error", len(out.Items))
	}
	// From the mark's schema read, not the grant check before it.
	if !strings.Contains(err.Error(), "resource types unreadable") {
		t.Errorf("err = %v, want the resource type read's error", err)
	}
	if len(out.Items) != 0 {
		t.Errorf("a failed list carried %d items", len(out.Items))
	}
}
