// relation_delete_tuple.go: a delete by composite key removes every tuple
// the key matches, and nothing else.
//
// The key is tenant, namespace, object type and ID, relation, subject type
// and ID. It leaves out subject_relation, so group:eng and group:eng#member
// on the same object are both matched. The REST delete reads the matches
// first and audits each one, so a store that removed only one of them would
// leave the audit trail naming a deletion that never happened.
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
// tenant, deletes by the key, and proves both matches are gone while the
// other two survive.
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

	if err := s.DeleteRelationTuple(ctx, "deltup-t1", "eng", "document", "doc1", "viewer", "group", "eng"); err != nil {
		t.Fatalf("DeleteRelationTuple: %v", err)
	}

	for name, tp := range map[string]*relation.Tuple{"group:eng": plain, "group:eng#member": member} {
		if _, err := s.GetRelation(ctx, tp.TenantID, tp.ID); !errors.Is(err, wardenerr.ErrRelationNotFound) {
			t.Errorf("%s survived a delete by its key: err=%v", name, err)
		}
	}
	for name, tp := range map[string]*relation.Tuple{"other namespace": otherNS, "other tenant": otherTenant} {
		if _, err := s.GetRelation(ctx, tp.TenantID, tp.ID); err != nil {
			t.Errorf("the %s tuple was removed: %v", name, err)
		}
	}
}
