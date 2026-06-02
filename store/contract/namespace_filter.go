package contract

import (
	"context"
	"strconv"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store"
)

// RunNamespaceFilterContract asserts that the namespace-scoped list queries on
// the Check() hot path correctly filter by a multi-element slice of namespace
// paths.
//
// This is the regression contract for the bug where the SQL stores wrote:
//
//	q.Where("namespace_path IN (?)", namespacePaths)   // namespacePaths is []string
//
// Grove's query builders bind one argument per "?" placeholder and do not
// expand slices, so the whole []string was bound to the single "?" and the
// driver (pgx / sqlite) rejected it — every Check() against a SQL store
// errored. The fix: postgres uses WhereArray("= ANY"); sqlite expands to
// IN (?, ?, …). The in-memory store iterates in Go and always satisfied this;
// this contract guards the SQL backends so the bug can't come back.
//
// Each case seeds rows across the ancestor namespaces ["eng/platform", "eng",
// ""] plus one decoy row at a non-ancestor "other" namespace that must be
// excluded from the result.
func RunNamespaceFilterContract(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("ListRolesForSubject", func(t *testing.T) { runListRolesForSubjectNS(t, mk) })
	t.Run("ListRolesForSubjectOnResource", func(t *testing.T) { runListRolesForSubjectOnResourceNS(t, mk) })
	t.Run("ListActivePolicies", func(t *testing.T) { runListActivePoliciesNS(t, mk) })
	t.Run("CheckDirectRelation", func(t *testing.T) { runCheckDirectRelationNS(t, mk) })
	t.Run("ListRelationSubjects", func(t *testing.T) { runListRelationSubjectsNS(t, mk) })
}

// ancestors mirrors warden.AncestorNamespaces("eng/platform"): the requested
// namespace and every parent up to root.
var nsAncestors = []string{"eng/platform", "eng", ""}

const nsDecoy = "other"

func runListRolesForSubjectNS(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	// One distinct role per namespace so we can assert exactly which rows
	// come back. The role's own namespace is irrelevant to the query — only
	// the assignment's namespace_path is filtered — but distinct slugs keep
	// the role uniqueness constraint happy.
	want := make(map[string]bool)
	for i, ns := range nsAncestors {
		rid := seedRole(t, s, "t1", ns, slugFor("rs", i))
		createAssignment(t, s, &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: ns,
			RoleID: rid, SubjectKind: "user", SubjectID: "alice",
		})
		want[rid.String()] = true
	}
	decoy := seedRole(t, s, "t1", nsDecoy, "rs-decoy")
	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: nsDecoy,
		RoleID: decoy, SubjectKind: "user", SubjectID: "alice",
	})

	got, err := s.ListRolesForSubject(ctx, "t1", nsAncestors, "user", "alice")
	if err != nil {
		t.Fatalf("ListRolesForSubject: %v", err)
	}
	assertRoleSet(t, got, want, decoy)
}

func runListRolesForSubjectOnResourceNS(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	want := make(map[string]bool)
	for i, ns := range nsAncestors {
		rid := seedRole(t, s, "t1", ns, slugFor("rsr", i))
		createAssignment(t, s, &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: ns,
			RoleID: rid, SubjectKind: "user", SubjectID: "alice",
			ResourceType: "doc", ResourceID: "doc1",
		})
		want[rid.String()] = true
	}
	decoy := seedRole(t, s, "t1", nsDecoy, "rsr-decoy")
	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: nsDecoy,
		RoleID: decoy, SubjectKind: "user", SubjectID: "alice",
		ResourceType: "doc", ResourceID: "doc1",
	})

	got, err := s.ListRolesForSubjectOnResource(ctx, "t1", nsAncestors, "user", "alice", "doc", "doc1")
	if err != nil {
		t.Fatalf("ListRolesForSubjectOnResource: %v", err)
	}
	assertRoleSet(t, got, want, decoy)
}

func runListActivePoliciesNS(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	want := make(map[string]bool)
	for i, ns := range nsAncestors {
		p := createPolicy(t, s, "t1", ns, slugFor("pol", i))
		want[p.String()] = true
	}
	decoy := createPolicy(t, s, "t1", nsDecoy, "pol-decoy")

	got, err := s.ListActivePolicies(ctx, "t1", nsAncestors)
	if err != nil {
		t.Fatalf("ListActivePolicies: %v", err)
	}
	gotSet := make(map[string]bool, len(got))
	for _, p := range got {
		gotSet[p.ID.String()] = true
	}
	for id := range want {
		if !gotSet[id] {
			t.Errorf("expected policy %s in result, missing", id)
		}
	}
	if gotSet[decoy.String()] {
		t.Errorf("decoy policy at %q namespace leaked into result", nsDecoy)
	}
}

func runCheckDirectRelationNS(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	// A tuple at ancestor "eng" must be visible from the cascaded list;
	// a tuple at the non-ancestor "other" namespace must not.
	createRelation(t, s, &relation.Tuple{
		TenantID: "t1", NamespacePath: "eng",
		ObjectType: "document", ObjectID: "doc1", Relation: "read",
		SubjectType: "user", SubjectID: "alice",
	})
	createRelation(t, s, &relation.Tuple{
		TenantID: "t1", NamespacePath: nsDecoy,
		ObjectType: "document", ObjectID: "doc2", Relation: "read",
		SubjectType: "user", SubjectID: "bob",
	})

	ok, err := s.CheckDirectRelation(ctx, "t1", nsAncestors, "document", "doc1", "read", "user", "alice")
	if err != nil {
		t.Fatalf("CheckDirectRelation (ancestor): %v", err)
	}
	if !ok {
		t.Errorf("relation at ancestor namespace should be found via cascaded list")
	}

	leaked, err := s.CheckDirectRelation(ctx, "t1", nsAncestors, "document", "doc2", "read", "user", "bob")
	if err != nil {
		t.Fatalf("CheckDirectRelation (decoy): %v", err)
	}
	if leaked {
		t.Errorf("relation at non-ancestor namespace must NOT be found")
	}
}

func runListRelationSubjectsNS(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	// Same object+relation, subjects spread across namespaces.
	createRelation(t, s, &relation.Tuple{
		TenantID: "t1", NamespacePath: "eng",
		ObjectType: "document", ObjectID: "doc1", Relation: "read",
		SubjectType: "user", SubjectID: "alice",
	})
	createRelation(t, s, &relation.Tuple{
		TenantID: "t1", NamespacePath: "",
		ObjectType: "document", ObjectID: "doc1", Relation: "read",
		SubjectType: "user", SubjectID: "carol",
	})
	createRelation(t, s, &relation.Tuple{
		TenantID: "t1", NamespacePath: nsDecoy,
		ObjectType: "document", ObjectID: "doc1", Relation: "read",
		SubjectType: "user", SubjectID: "dave",
	})

	tuples, err := s.ListRelationSubjects(ctx, "t1", nsAncestors, "document", "doc1", "read")
	if err != nil {
		t.Fatalf("ListRelationSubjects: %v", err)
	}
	got := make(map[string]bool, len(tuples))
	for _, tup := range tuples {
		got[tup.SubjectID] = true
	}
	for _, want := range []string{"alice", "carol"} {
		if !got[want] {
			t.Errorf("expected subject %q from ancestor namespace, missing", want)
		}
	}
	if got["dave"] {
		t.Errorf("subject from non-ancestor %q namespace leaked into result", nsDecoy)
	}
}

// ───── helpers ─────

func createRelation(t *testing.T, s store.Store, tup *relation.Tuple) {
	t.Helper()
	if err := s.CreateRelation(context.Background(), tup); err != nil {
		t.Fatalf("create relation (ns=%q): %v", tup.NamespacePath, err)
	}
}

func slugFor(prefix string, i int) string {
	return prefix + "-" + strconv.Itoa(i)
}

func createAssignment(t *testing.T, s store.Store, a *assignment.Assignment) {
	t.Helper()
	if err := s.CreateAssignment(context.Background(), a); err != nil {
		t.Fatalf("create assignment (ns=%q): %v", a.NamespacePath, err)
	}
}

func createPolicy(t *testing.T, s store.Store, tenant, ns, name string) id.PolicyID {
	t.Helper()
	p := &policy.Policy{
		ID: id.NewPolicyID(), TenantID: tenant, NamespacePath: ns,
		Name: name, Effect: policy.EffectAllow, IsActive: true,
		// Postgres has NOT NULL JSONB columns for these slices; supply empty
		// (not nil) so the marshaler emits "[]" rather than NULL.
		Subjects:    []policy.SubjectMatch{},
		Actions:     []string{},
		Resources:   []string{},
		Conditions:  []policy.Condition{},
		Obligations: []string{},
	}
	if err := s.CreatePolicy(context.Background(), p); err != nil {
		t.Fatalf("create policy (ns=%q): %v", ns, err)
	}
	return p.ID
}

func assertRoleSet(t *testing.T, got []id.RoleID, want map[string]bool, decoy id.RoleID) {
	t.Helper()
	gotSet := make(map[string]bool, len(got))
	for _, rid := range got {
		gotSet[rid.String()] = true
	}
	for rid := range want {
		if !gotSet[rid] {
			t.Errorf("expected role %s in result, missing", rid)
		}
	}
	if gotSet[decoy.String()] {
		t.Errorf("decoy role at %q namespace leaked into result", nsDecoy)
	}
}
