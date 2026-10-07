package resourcetype

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/wardenerr"
)

// fakeTypes answers GetResourceTypeByName from a map keyed by
// tenant/namespace/name, the way the stores do: a miss is
// ErrResourceTypeNotFound.
type fakeTypes struct {
	rows map[string]*ResourceType
	fail error
}

func (f *fakeTypes) GetResourceTypeByName(_ context.Context, tenantID, ns, name string) (*ResourceType, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	if rt, ok := f.rows[tenantID+"|"+ns+"|"+name]; ok {
		return rt, nil
	}
	return nil, fmt.Errorf("resource type %q in ns %q: %w", name, ns, wardenerr.ErrResourceTypeNotFound)
}

func (f *fakeTypes) put(tenantID string, rt *ResourceType) {
	if f.rows == nil {
		f.rows = map[string]*ResourceType{}
	}
	rt.TenantID = tenantID
	f.rows[tenantID+"|"+rt.NamespacePath+"|"+rt.Name] = rt
}

func TestSubjectAllowedFollowsTheDSL(t *testing.T) {
	// From dsl/ast.go SubjectType and the DSL reference: an entry is a bare
	// type or a subject set `type#relation`. The DSL has no wildcard; a
	// quoted "user:*" is a type name like any other.
	cases := []struct {
		name    string
		allowed []string
		typ     string
		rel     string
		want    bool
	}{
		{"bare type admits that type", []string{"user"}, "user", "", true},
		{"bare type refuses another type", []string{"user"}, "team", "", false},
		{"bare group does not admit a subject set of group", []string{"group"}, "group", "member", false},
		{"subject set admits that type and relation", []string{"group#member"}, "group", "member", true},
		{"subject set refuses the bare type", []string{"group#member"}, "group", "", false},
		{"subject set refuses another relation", []string{"group#member"}, "group", "admin", false},
		{"any entry of several", []string{"user", "group#member"}, "group", "member", true},
		{"quoted user:* is a literal type, not a wildcard", []string{"user:*"}, "user", "", false},
		{"quoted user:* admits its literal type", []string{"user:*"}, "user:*", "", true},
		{"empty list admits a bare type", nil, "user", "", true},
		{"empty list admits another bare type", []string{}, "group", "", true},
		{"empty list admits a subject set", nil, "group", "member", true},
		{"no case folding", []string{"User"}, "user", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SubjectAllowed(c.allowed, c.typ, c.rel); got != c.want {
				t.Errorf("SubjectAllowed(%q, %q, %q) = %v, want %v", c.allowed, c.typ, c.rel, got, c.want)
			}
		})
	}
}

func docType(ns string) *ResourceType {
	return &ResourceType{
		NamespacePath: ns, Name: "document",
		Relations: []RelationDef{
			{Name: "owner", AllowedSubjects: []string{"user"}},
			{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
		},
	}
}

func tuple(ns, rel, subjType, subjRel string) *relation.Tuple {
	return &relation.Tuple{
		TenantID: "t1", NamespacePath: ns,
		ObjectType: "document", ObjectID: "d1", Relation: rel,
		SubjectType: subjType, SubjectID: "x", SubjectRelation: subjRel,
	}
}

func TestCheckTupleDeclared(t *testing.T) {
	ctx := context.Background()
	s := &fakeTypes{}
	s.put("t1", docType("eng"))
	// Another tenant's declaration never governs t1.
	s.put("t2", &ResourceType{NamespacePath: "", Name: "document"})

	ok := []struct {
		name string
		t    *relation.Tuple
	}{
		{"undeclared object type writes", &relation.Tuple{TenantID: "t1", ObjectType: "folder", ObjectID: "f", Relation: "anything", SubjectType: "team", SubjectID: "x"}},
		{"declared relation and allowed subject", tuple("eng", "viewer", "user", "")},
		{"allowed subject set", tuple("eng", "viewer", "group", "member")},
		{"ancestor governs a child namespace", tuple("eng/platform", "owner", "user", "")},
		{"a sibling's declaration does not govern", tuple("sales", "nonsense", "team", "")},
		{"a descendant's declaration does not govern", tuple("", "nonsense", "team", "")},
	}
	for _, c := range ok {
		if err := CheckTupleDeclared(ctx, s, c.t); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	refused := []struct {
		name string
		t    *relation.Tuple
		msg  string
	}{
		{
			"undeclared relation", tuple("eng", "editor", "user", ""),
			`tuple document:d1#editor@user:x in namespace "eng" is refused: resource type "document" in namespace "eng" declares no relation "editor" (its relations are "owner", "viewer")`,
		},
		{
			"disallowed subject", tuple("eng", "owner", "group", "member"),
			`tuple document:d1#owner@group:x#member in namespace "eng" is refused: relation "owner" of resource type "document" in namespace "eng" allows subjects "user", not "group#member"`,
		},
		{
			"ancestor refuses in a child namespace", tuple("eng/platform", "viewer", "team", ""),
			`tuple document:d1#viewer@team:x in namespace "eng/platform" is refused: relation "viewer" of resource type "document" in namespace "eng" allows subjects "user", "group#member", not "team"`,
		},
	}
	for _, c := range refused {
		err := CheckTupleDeclared(ctx, s, c.t)
		var ue *UndeclaredTupleError
		if !errors.As(err, &ue) {
			t.Errorf("%s: err = %v, want *UndeclaredTupleError", c.name, err)
			continue
		}
		if err.Error() != c.msg {
			t.Errorf("%s:\n got %s\nwant %s", c.name, err.Error(), c.msg)
		}
	}
}

func TestCheckTupleDeclaredNearestWins(t *testing.T) {
	// The root declares viewer; eng redeclares document without it. A tuple
	// in eng/platform is governed by eng's, the nearest, so it is refused
	// even though the root would allow it.
	ctx := context.Background()
	s := &fakeTypes{}
	s.put("t1", docType(""))
	s.put("t1", &ResourceType{NamespacePath: "eng", Name: "document", Relations: []RelationDef{{Name: "owner", AllowedSubjects: []string{"user"}}}})

	if err := CheckTupleDeclared(ctx, s, tuple("", "viewer", "user", "")); err != nil {
		t.Errorf("root tuple: %v", err)
	}
	err := CheckTupleDeclared(ctx, s, tuple("eng/platform", "viewer", "user", ""))
	var ue *UndeclaredTupleError
	if !errors.As(err, &ue) || ue.Namespace != "eng" {
		t.Fatalf("err = %v, want a refusal by eng's resource type", err)
	}
}

func TestCheckTupleDeclaredEmptyDeclarations(t *testing.T) {
	// A relation that lists no subject types takes any subject, but it must
	// still be declared; a listed relation still restricts.
	ctx := context.Background()
	s := &fakeTypes{}
	s.put("t1", &ResourceType{Name: "document", Relations: []RelationDef{
		{Name: "on call"},
		{Name: "owner", AllowedSubjects: []string{"user"}},
	}})
	s.put("t1", &ResourceType{Name: "bare"})

	for _, subj := range []struct{ typ, rel string }{{"user", ""}, {"group", ""}, {"group", "member"}} {
		if err := CheckTupleDeclared(ctx, s, tuple("", "on call", subj.typ, subj.rel)); err != nil {
			t.Errorf("empty list refused %s#%s: %v", subj.typ, subj.rel, err)
		}
	}

	err := CheckTupleDeclared(ctx, s, tuple("", "owner", "group", "member"))
	want := `tuple document:d1#owner@group:x#member in the tenant root is refused: relation "owner" of resource type "document" in the tenant root allows subjects "user", not "group#member"`
	if err == nil || err.Error() != want {
		t.Errorf("listed relation: got %v\nwant %s", err, want)
	}

	err = CheckTupleDeclared(ctx, s, tuple("", "editor", "user", ""))
	want = `tuple document:d1#editor@user:x in the tenant root is refused: resource type "document" in the tenant root declares no relation "editor" (its relations are "on call", "owner")`
	if err == nil || err.Error() != want {
		t.Errorf("undeclared relation: got %v\nwant %s", err, want)
	}

	bare := &relation.Tuple{TenantID: "t1", ObjectType: "bare", ObjectID: "b", Relation: "r", SubjectType: "user", SubjectID: "x"}
	err = CheckTupleDeclared(ctx, s, bare)
	want = `tuple bare:b#r@user:x in the tenant root is refused: resource type "bare" in the tenant root declares no relation "r" (it declares no relations)`
	if err == nil || err.Error() != want {
		t.Errorf("got %v\nwant %s", err, want)
	}
}

func TestCheckTupleDeclaredReturnsAReadError(t *testing.T) {
	// A guard that cannot read the schema refuses rather than writes.
	boom := errors.New("store down")
	err := CheckTupleDeclared(context.Background(), &fakeTypes{fail: boom}, tuple("eng", "viewer", "user", ""))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the read error", err)
	}
	var ue *UndeclaredTupleError
	if errors.As(err, &ue) {
		t.Error("a read error must not read as a declaration refusal")
	}
	if !strings.Contains(err.Error(), `"document"`) {
		t.Errorf("err = %v, want it to name the resource type it was reading", err)
	}
}

func TestUndeclaredReasonIsTheRefusalWithoutItsHead(t *testing.T) {
	// Reason is what a stored tuple is marked with: true of a tuple that
	// was written, which "is refused" is not.
	s := &fakeTypes{}
	s.put("t1", docType("eng"))
	err := CheckTupleDeclared(context.Background(), s, tuple("eng/platform", "viewer", "team", ""))
	var u *UndeclaredTupleError
	if !errors.As(err, &u) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	want := `relation "viewer" of resource type "document" in namespace "eng" allows subjects "user", "group#member", not "team"`
	if u.Reason() != want {
		t.Errorf("reason:\n got %s\nwant %s", u.Reason(), want)
	}
	head := `tuple document:d1#viewer@team:x in namespace "eng/platform" is refused: `
	if u.Error() != head+want {
		t.Errorf("error:\n got %s\nwant %s", u.Error(), head+want)
	}
}
