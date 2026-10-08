// relation_delete_tuple.go: a delete by composite key removes exactly the
// tuple the key names, and nothing else.
//
// The key is tenant, namespace, object type and ID, relation, subject type
// and ID, and subject relation. An empty subject relation names the direct
// tuple, so group:eng and group:eng#member on the same object are two keys:
// deleting one leaves the other. The REST delete reads the match first and
// audits it, so a store that also removed the other tuple would remove a
// grant the audit trail never names.
package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/wardenerr"
)

// RunRelationDeleteTupleContract seeds two tuples that differ only in
// subject_relation, plus the same key in another namespace and another
// tenant. It deletes by the key with an empty subject relation and proves
// only the direct tuple is gone, then with "member" and proves only the
// subject set is gone. The other namespace and tenant survive both.
func RunRelationDeleteTupleContract(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	mkTuple := func(tenant, ns, subjectRelation string) *relation.Tuple {
		tp := &relation.Tuple{
			TenantID: tenant, NamespacePath: ns,
			ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
			SubjectType: "group", SubjectID: "eng", SubjectRelation: subjectRelation,
		}
		createRelation(t, s, tp)
		return tp
	}
	plain := mkTuple("deltup-t1", "eng", "")
	member := mkTuple("deltup-t1", "eng", "member")
	otherNS := mkTuple("deltup-t1", "", "")
	otherTenant := mkTuple("deltup-t2", "eng", "")

	gone := func(name string, tp *relation.Tuple) {
		t.Helper()
		if _, err := s.GetRelation(ctx, tp.TenantID, tp.ID); !errors.Is(err, wardenerr.ErrRelationNotFound) {
			t.Errorf("%s survived a delete by its key: err=%v", name, err)
		}
	}
	kept := func(name string, tp *relation.Tuple) {
		t.Helper()
		if _, err := s.GetRelation(ctx, tp.TenantID, tp.ID); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}

	if err := s.DeleteRelationTuple(ctx, "deltup-t1", "eng", "document", "doc1", "viewer", "group", "eng", ""); err != nil {
		t.Fatalf("DeleteRelationTuple(group:eng): %v", err)
	}
	gone("group:eng", plain)
	kept("group:eng#member, by a delete of group:eng,", member)
	kept("the other namespace's tuple", otherNS)
	kept("the other tenant's tuple", otherTenant)

	if err := s.DeleteRelationTuple(ctx, "deltup-t1", "eng", "document", "doc1", "viewer", "group", "eng", "member"); err != nil {
		t.Fatalf("DeleteRelationTuple(group:eng#member): %v", err)
	}
	gone("group:eng#member", member)
	kept("the other namespace's tuple", otherNS)
	kept("the other tenant's tuple", otherTenant)

	// The reverse order: a delete of the subject set leaves the direct
	// tuple.
	plain = mkTuple("deltup-t1", "eng", "")
	member = mkTuple("deltup-t1", "eng", "member")
	if err := s.DeleteRelationTuple(ctx, "deltup-t1", "eng", "document", "doc1", "viewer", "group", "eng", "member"); err != nil {
		t.Fatalf("DeleteRelationTuple(group:eng#member): %v", err)
	}
	gone("group:eng#member", member)
	kept("group:eng, by a delete of group:eng#member,", plain)
}
