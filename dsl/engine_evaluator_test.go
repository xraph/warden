package dsl

import (
	"context"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store/memory"
)

// TestEngineEvaluator_EndToEnd verifies the full path: DSL → applier
// → engine.Check using a resource-type permission expression.
//
// This is the integration test that proves Phase B+C+C.5 works together:
// the user defines `permission read = viewer or editor or parent->read`
// in source, applies it, writes some tuples, and Check returns Allow
// based purely on relation walking (no RBAC role).
func TestEngineEvaluator_EndToEnd(t *testing.T) {
	src := `
warden config 1
tenant t1

resource folder {
    relation owner: user
    relation viewer: user
    permission view = owner or viewer
}

resource doc {
    relation parent: folder
    relation owner: user
    relation viewer: user
    permission read = owner or viewer or parent->view
}
`
	prog, errs := Parse("test.warden", []byte(src))
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	s := memory.New()
	ev := NewEngineEvaluator(s)
	eng, err := warden.NewEngine(
		warden.WithStore(s),
		warden.WithExpressionEvaluator(ev),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Wire up the relation graph:
	//   folder/root has alice as viewer
	//   document/d1's parent is folder/root
	mustTuple(t, s, "t1", "folder", "root", "viewer", "user", "alice")
	mustTuple(t, s, "t1", "doc", "d1", "parent", "folder", "root")
	// Also a direct viewer on document.
	mustTuple(t, s, "t1", "doc", "d2", "viewer", "user", "bob")

	ctx := warden.WithTenant(context.Background(), "", "t1")

	// Alice can read d1 via parent->view traversal.
	checkAllowed(t, eng, ctx, "alice", "read", "doc", "d1", true,
		"alice should read d1 via parent->view")

	// Bob can read d2 directly via `viewer`.
	checkAllowed(t, eng, ctx, "bob", "read", "doc", "d2", true,
		"bob should read d2 directly")

	// Carol can read neither.
	checkAllowed(t, eng, ctx, "carol", "read", "doc", "d1", false,
		"carol has no relation to d1")
	checkAllowed(t, eng, ctx, "carol", "read", "doc", "d2", false,
		"carol has no relation to d2")
}

func mustTuple(t *testing.T, s *memory.Store, tenant, objType, objID, rel, subjType, subjID string) {
	t.Helper()
	if err := s.CreateRelation(context.Background(), &relation.Tuple{
		ID:          id.NewRelationID(),
		TenantID:    tenant,
		ObjectType:  objType,
		ObjectID:    objID,
		Relation:    rel,
		SubjectType: subjType,
		SubjectID:   subjID,
	}); err != nil {
		t.Fatal(err)
	}
}

func checkAllowed(t *testing.T, eng *warden.Engine, ctx context.Context,
	subject, action, resType, resID string, want bool, msg string) {
	t.Helper()
	result, err := eng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: subject},
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resType, ID: resID},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Allowed != want {
		t.Errorf("%s: got allowed=%v (decision=%s reason=%s), want %v",
			msg, result.Allowed, result.Decision, result.Reason, want)
	}
}
