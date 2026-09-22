package dsl

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store/memory"
)

func writeTuple(t *testing.T, s *memory.Store, objType, objID, rel, subjType, subjID string) {
	t.Helper()
	if err := s.CreateRelation(context.Background(), &relation.Tuple{
		ID:          id.NewRelationID(),
		TenantID:    "t1",
		ObjectType:  objType,
		ObjectID:    objID,
		Relation:    rel,
		SubjectType: subjType,
		SubjectID:   subjID,
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEval_DirectRelation(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	expr, errs := CompileExpr("test", "viewer")
	if len(errs) > 0 {
		t.Fatalf("compile: %v", errs)
	}

	writeTuple(t, s, "doc", "d1", "viewer", "user", "alice")

	ec := EvalContext{
		TenantID:    "t1",
		ObjectType:  "doc",
		ObjectID:    "d1",
		SubjectType: "user",
		SubjectID:   "alice",
	}
	ok, err := ev.Eval(context.Background(), expr, ec)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected direct relation match")
	}

	// Wrong subject — should miss.
	ec.SubjectID = "bob"
	ok, _ = ev.Eval(context.Background(), expr, ec)
	if ok {
		t.Fatal("expected miss for unrelated subject")
	}
}

func TestEval_OrAndNot(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)

	// Alice is editor; Bob is viewer; Carol is banned.
	writeTuple(t, s, "doc", "d1", "editor", "user", "alice")
	writeTuple(t, s, "doc", "d1", "viewer", "user", "bob")
	writeTuple(t, s, "doc", "d1", "banned", "user", "carol")

	tests := []struct {
		name    string
		expr    string
		subject string
		want    bool
	}{
		{"or - alice as editor", "viewer or editor", "alice", true},
		{"or - bob as viewer", "viewer or editor", "bob", true},
		{"or - carol", "viewer or editor", "carol", false},
		{"and - alice editor and not banned", "editor and not banned", "alice", true},
		{"and - carol editor and not banned", "editor and not banned", "carol", false}, // not editor
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, errs := CompileExpr("test", tt.expr)
			if len(errs) > 0 {
				t.Fatalf("compile %q: %v", tt.expr, errs)
			}
			ec := EvalContext{
				TenantID:    "t1",
				ObjectType:  "doc",
				ObjectID:    "d1",
				SubjectType: "user",
				SubjectID:   tt.subject,
			}
			got, err := ev.Eval(context.Background(), expr, ec)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEval_Traversal(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)

	// folder/parent has alice as viewer.
	// document/child has its parent set to folder/parent.
	writeTuple(t, s, "folder", "parent", "viewer", "user", "alice")
	writeTuple(t, s, "doc", "child", "parent", "folder", "parent")

	// `parent->viewer` should match: hop into folder/parent, then check
	// viewer.
	expr, errs := CompileExpr("test", "parent->viewer")
	if len(errs) > 0 {
		t.Fatalf("compile: %v", errs)
	}

	ec := EvalContext{
		TenantID:    "t1",
		ObjectType:  "doc",
		ObjectID:    "child",
		SubjectType: "user",
		SubjectID:   "alice",
	}
	ok, err := ev.Eval(context.Background(), expr, ec)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected traversal match")
	}
}

func TestEval_Cache(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	expr1, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer or editor")
	expr2, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer or editor")
	if expr1 != expr2 {
		t.Fatal("expected same cached AST")
	}

	// Invalidate and confirm we get a fresh AST.
	ev.Invalidate("t1", "doc")
	expr3, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer or editor")
	if expr1 == expr3 {
		t.Fatal("expected fresh AST after invalidation")
	}
}

// TestEval_CacheVersioned_RecompilesOnNewerUpdatedAt verifies M5: a cache
// entry compiled with an older UpdatedAt is treated as stale (and
// recompiled) once a call arrives with a newer one — as happens when a
// resource type's permission expression is edited between two Checks.
func TestEval_CacheVersioned_RecompilesOnNewerUpdatedAt(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	exprA, diags := ev.CompileAndCacheVersioned("t1", "", "doc", "read", "viewer", t0)
	if len(diags) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	// Same UpdatedAt: must reuse the cached AST, not recompile.
	exprSame, diags := ev.CompileAndCacheVersioned("t1", "", "doc", "read", "viewer", t0)
	if len(diags) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if exprA != exprSame {
		t.Fatal("expected the same cached AST for an unchanged UpdatedAt")
	}

	// Newer UpdatedAt (the expression source also changed, as it would in
	// practice): must recompile rather than serve the stale AST.
	exprB, diags := ev.CompileAndCacheVersioned("t1", "", "doc", "read", "editor", t1)
	if len(diags) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if exprA == exprB {
		t.Fatal("expected a fresh AST once UpdatedAt advanced")
	}

	// The now-cached entry (compiled at t1) must be served for a call at
	// the same or an older UpdatedAt.
	exprC, diags := ev.CompileAndCacheVersioned("t1", "", "doc", "read", "editor", t1)
	if len(diags) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if exprB != exprC {
		t.Fatal("expected the freshly compiled AST to now be cached")
	}
}

// TestEval_CompileAndCache_IgnoresVersioning verifies the plain
// CompileAndCache path is unaffected by staleness tracking: it always
// trusts whatever is cached, matching its pre-M5 behavior exactly.
func TestEval_CompileAndCache_IgnoresVersioning(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Seed the cache via the versioned path with a real timestamp.
	exprA, _ := ev.CompileAndCacheVersioned("t1", "", "doc", "read", "viewer", t1)

	// The plain path (zero UpdatedAt) must still hit the cache rather than
	// treating the entry as stale.
	exprB, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	if exprA != exprB {
		t.Fatal("expected CompileAndCache to reuse the versioned cache entry")
	}
}

func TestEval_DepthBound(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	// A chain of folders, each parent of the next, but no terminating viewer.
	// Walker should bottom out at depth and return false rather than recurse forever.
	writeTuple(t, s, "folder", "f1", "parent", "folder", "f2")
	writeTuple(t, s, "folder", "f2", "parent", "folder", "f3")
	writeTuple(t, s, "folder", "f3", "parent", "folder", "f1") // cycle

	expr, _ := CompileExpr("test", "parent->parent->parent->viewer")
	ec := EvalContext{
		TenantID:    "t1",
		ObjectType:  "folder",
		ObjectID:    "f1",
		SubjectType: "user",
		SubjectID:   "alice",
		MaxDepth:    5,
	}
	ok, err := ev.Eval(context.Background(), expr, ec)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected miss; depth bound should terminate cycle")
	}
}
