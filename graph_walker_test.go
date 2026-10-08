package warden

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store/memory"
)

// fakeGraphMetrics records the calls the graph walker makes, for assertions
// independent of the engine's own Metrics wiring.
type fakeGraphMetrics struct {
	NoopMetrics
	budgetExceeded int
	nodesVisited   []int
}

func (f *fakeGraphMetrics) GraphBudgetExceeded()    { f.budgetExceeded++ }
func (f *fakeGraphMetrics) GraphNodesVisited(n int) { f.nodesVisited = append(f.nodesVisited, n) }

func TestGraphWalker_PlainSubjectIsNotASubjectSet(t *testing.T) {
	// document:1#viewer@group:eng (no SubjectRelation: a literal grant to
	// the group object itself, NOT "members of group:eng's viewer
	// relation"). group:eng#viewer@user:bob must NOT transitively grant
	// bob viewer access on document:1, that would be the H9 semantic bug.
	ctx := context.Background()
	s := memory.New()
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "1", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng",
	})
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "group", ObjectID: "eng", Relation: "viewer",
		SubjectType: "user", SubjectID: "bob",
	})

	w := NewGraphWalker(10, 0, 0, nil)
	allowed, _, err := w.Walk(ctx, s, "t1", "", &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "bob"},
		Action:   Action{Name: "viewer"},
		Resource: Resource{Type: "document", ID: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("plain (non-subject-set) group tuple must not transitively grant access")
	}
}

func TestGraphWalker_SubjectSetGrants(t *testing.T) {
	// document:1#viewer@group:eng#member (subject SET: every member of
	// group:eng's `member` relation is a viewer). group:eng#member@user:bob
	// must grant bob viewer access on document:1.
	ctx := context.Background()
	s := memory.New()
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "1", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: "member",
	})
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "group", ObjectID: "eng", Relation: "member",
		SubjectType: "user", SubjectID: "bob",
	})

	w := NewGraphWalker(10, 0, 0, nil)
	allowed, path, err := w.Walk(ctx, s, "t1", "", &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "bob"},
		Action:   Action{Name: "viewer"},
		Resource: Resource{Type: "document", ID: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("subject-set tuple should grant transitive access via group membership")
	}
	if path == "" {
		t.Fatal("expected a non-empty match path")
	}
}

func TestGraphWalker_FanoutBudgetExceeded(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	// 2000 direct members of a group whose `member` relation is the
	// subject set for document:1's viewer relation.
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "1", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: "member",
	})
	for i := 0; i < 2000; i++ {
		_ = s.CreateRelation(ctx, &relation.Tuple{
			TenantID: "t1", ObjectType: "group", ObjectID: "eng", Relation: "member",
			SubjectType: "user", SubjectID: "user-" + strconv.Itoa(i),
		})
	}

	metrics := &fakeGraphMetrics{}
	w := NewGraphWalker(10, 5000, 100, metrics)
	allowed, _, err := w.Walk(ctx, s, "t1", "", &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "user-1999"},
		Action:   Action{Name: "viewer"},
		Resource: Resource{Type: "document", ID: "1"},
	})
	if allowed {
		t.Fatal("expected deny when fan-out exceeds MaxGraphFanout")
	}
	if err == nil || !errors.Is(err, ErrGraphBudgetExceeded) {
		t.Fatalf("expected ErrGraphBudgetExceeded, got %v", err)
	}
	if metrics.budgetExceeded == 0 {
		t.Fatal("expected GraphBudgetExceeded metric to be recorded")
	}
}

func TestGraphWalker_VisitedBudgetExceeded(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	// A long chain: document:1 -> group:0#member -> group:1#member -> ... a
	// chain longer than maxVisited, each hop a fresh subject-set edge.
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "1", Relation: "viewer",
		SubjectType: "group", SubjectID: "0", SubjectRelation: "member",
	})
	for i := 0; i < 50; i++ {
		_ = s.CreateRelation(ctx, &relation.Tuple{
			TenantID: "t1", ObjectType: "group", ObjectID: strconv.Itoa(i), Relation: "member",
			SubjectType: "group", SubjectID: strconv.Itoa(i + 1), SubjectRelation: "member",
		})
	}
	_ = s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "group", ObjectID: "50", Relation: "member",
		SubjectType: "user", SubjectID: "bob",
	})

	metrics := &fakeGraphMetrics{}
	// maxDepth generous, maxVisited tiny so the budget trips first.
	w := NewGraphWalker(100, 5, 1000, metrics)
	allowed, _, err := w.Walk(ctx, s, "t1", "", &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "bob"},
		Action:   Action{Name: "viewer"},
		Resource: Resource{Type: "document", ID: "1"},
	})
	if allowed {
		t.Fatal("expected deny when visited-node budget is exceeded")
	}
	if err == nil || !errors.Is(err, ErrGraphBudgetExceeded) {
		t.Fatalf("expected ErrGraphBudgetExceeded, got %v", err)
	}
	if metrics.budgetExceeded == 0 {
		t.Fatal("expected GraphBudgetExceeded metric to be recorded")
	}
}

func TestGraphWalker_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := memory.New()
	_ = s.CreateRelation(context.Background(), &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "1", Relation: "viewer",
		SubjectType: "user", SubjectID: "bob",
	})

	w := NewGraphWalker(10, 0, 0, nil)
	_, _, err := w.Walk(ctx, s, "t1", "", &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "someone-else"},
		Action:   Action{Name: "viewer"},
		Resource: Resource{Type: "document", ID: "1"},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
