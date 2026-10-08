package warden

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/memory"
)

// waitForCheckLog polls until the writer has flushed at least one entry for
// tenant t1, and returns the newest one's reason and decision.
func waitForCheckLog(t *testing.T, s *memory.Store) (reason, decision, errText string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := s.ListCheckLogs(context.Background(), checklogFilterForTenant("t1"))
		if err != nil {
			t.Fatalf("list check logs: %v", err)
		}
		if len(entries) > 0 {
			e := entries[0]
			return e.Reason, e.Decision, e.Error
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no check log entry was written")
	return "", "", ""
}

// seedDeepChain builds document:1#viewer -> group:0#member -> ... -> group:n
// with bob at the end, so a walk with a small budget cannot reach him.
func seedDeepChain(t *testing.T, s *memory.Store, n int) {
	t.Helper()
	ctx := context.Background()
	mk := func(tp *relation.Tuple) {
		tp.TenantID = "t1"
		if err := s.CreateRelation(ctx, tp); err != nil {
			t.Fatalf("create relation: %v", err)
		}
	}
	mk(&relation.Tuple{ObjectType: "document", ObjectID: "1", Relation: "viewer", SubjectType: "group", SubjectID: "0", SubjectRelation: "member"})
	for i := 0; i < n; i++ {
		mk(&relation.Tuple{ObjectType: "group", ObjectID: strconv.Itoa(i), Relation: "member", SubjectType: "group", SubjectID: strconv.Itoa(i + 1), SubjectRelation: "member"})
	}
	mk(&relation.Tuple{ObjectType: "group", ObjectID: strconv.Itoa(n), Relation: "member", SubjectType: "user", SubjectID: "bob"})
}

func bobViews() *CheckRequest {
	return &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "bob"},
		Action:   Action{Name: "viewer"},
		Resource: Resource{Type: "document", ID: "1"},
		TenantID: "t1",
	}
}

// TestCheck_TruncatedGraphWalkIsRecordedInTheCheckLog: a denial because the
// walk ran out of budget is not the same fact as a denial because no
// relation exists. An auditor reading the check log has to be able to tell
// them apart.
func TestCheck_TruncatedGraphWalkIsRecordedInTheCheckLog(t *testing.T) {
	cases := map[string]func(*Config){
		"visited budget": func(c *Config) { c.MaxGraphVisited = 5 },
		"depth limit":    func(c *Config) { c.MaxGraphDepth = 3 },
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			s := memory.New()
			seedDeepChain(t, s, 30)
			cfg := DefaultConfig()
			tweak(&cfg)
			eng, err := NewEngine(WithStore(s), WithConfig(cfg))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = eng.Stop(context.Background()) })

			res, err := eng.Check(context.Background(), bobViews())
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if res.Allowed {
				t.Fatal("a walk that could not reach bob allowed him")
			}
			if !strings.Contains(res.Reason, "graph traversal") {
				t.Errorf("result reason = %q, want it to say the graph walk was truncated", res.Reason)
			}
			reason, _, _ := waitForCheckLog(t, s)
			if !strings.Contains(reason, "graph traversal") {
				t.Errorf("check log reason = %q, want it to say the graph walk was truncated", reason)
			}
		})
	}
}

func TestCheck_AnAbsentRelationIsNotReportedAsTruncated(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	res, err := eng.Check(context.Background(), bobViews())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Reason, "graph traversal") {
		t.Errorf("reason %q claims truncation for a plain miss", res.Reason)
	}
}

// failingRoleStore fails the role lookups the ABAC path uses when RBAC is
// switched off.
type failingRoleStore struct{ store.Store }

func (failingRoleStore) ListRolesForSubject(context.Context, string, []string, string, string) ([]id.RoleID, error) {
	return nil, errors.New("roles unavailable")
}

// TestCheck_RoleResolutionFailureFailsClosedWhenRBACIsOff: with RBAC off, a
// failed role lookup used to be logged and skipped, leaving the role list
// empty, so a deny policy scoped to a role stopped matching and the check
// carried on toward an allow. It has to fail the check instead.
func TestCheck_RoleResolutionFailureFailsClosedWhenRBACIsOff(t *testing.T) {
	s := memory.New()
	if err := s.CreatePolicy(context.Background(), &policy.Policy{
		TenantID: "t1", Name: "deny-contractors", Effect: policy.EffectDeny, IsActive: true,
		Subjects:  []policy.SubjectMatch{{Kind: "user", Role: "contractor"}},
		Actions:   []string{"read"},
		Resources: []string{"document"},
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.CreateRelation(context.Background(), &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "d1", Relation: "read",
		SubjectType: "user", SubjectID: "carol",
	}); err != nil {
		t.Fatalf("create relation: %v", err)
	}

	off := false
	cfg := DefaultConfig()
	cfg.EnableRBAC = &off
	eng, err := NewEngine(WithStore(failingRoleStore{s}), WithConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	res, err := eng.Check(context.Background(), &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "carol"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "d1"},
		TenantID: "t1",
	})
	if err == nil {
		t.Fatalf("a failed role lookup did not fail the check; result = %+v", res)
	}
	if !strings.Contains(err.Error(), "roles unavailable") {
		t.Errorf("error = %v, want the role lookup failure", err)
	}
	_, decision, errText := waitForCheckLog(t, s)
	if decision != "error" || errText == "" {
		t.Errorf("check log decision/error = %q/%q, want an error entry", decision, errText)
	}
}

// storeErrorRecorder captures the op labels StoreError is called with.
type storeErrorRecorder struct {
	NoopMetrics
	mu  sync.Mutex
	ops []string
}

func (r *storeErrorRecorder) StoreError(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op)
}

func (r *storeErrorRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ops...)
}

type errEvaluator struct{}

func (errEvaluator) Evaluate(context.Context, []*policy.Policy, *CheckRequest, []string) (*CheckResult, error) {
	return nil, errors.New("condition failed to evaluate")
}

// TestCheck_OnlyStoreErrorsCountAsStoreErrors: a policy evaluator failure is
// not a store error and must not inflate that metric, and a real store
// failure is counted once under its own label, not a second time as "check".
func TestCheck_OnlyStoreErrorsCountAsStoreErrors(t *testing.T) {
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "d1"},
		TenantID: "t1",
	}

	t.Run("evaluator error", func(t *testing.T) {
		rec := &storeErrorRecorder{}
		eng, err := NewEngine(WithStore(memory.New()), WithMetrics(rec), WithEvaluator(errEvaluator{}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = eng.Stop(context.Background()) })
		if _, err := eng.Check(context.Background(), req); err == nil {
			t.Fatal("expected the evaluator error to fail the check")
		}
		if ops := rec.snapshot(); len(ops) != 0 {
			t.Errorf("StoreError called with %v for a non-store failure", ops)
		}
	})

	t.Run("store error", func(t *testing.T) {
		rec := &storeErrorRecorder{}
		eng, err := NewEngine(WithStore(failingRoleStore{memory.New()}), WithMetrics(rec))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = eng.Stop(context.Background()) })
		if _, err := eng.Check(context.Background(), req); err == nil {
			t.Fatal("expected the store error to fail the check")
		}
		ops := rec.snapshot()
		if len(ops) != 1 || ops[0] != "list_roles_for_subject" {
			t.Errorf("StoreError ops = %v, want exactly [list_roles_for_subject]", ops)
		}
	})
}
