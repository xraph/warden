package warden

import (
	"context"
	"testing"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// drainCheckLogs polls the store until it observes at least n entries for
// tenantID, or fails the test after a timeout. The writer batches
// asynchronously, so a direct read right after Check can race the flush.
func drainCheckLogs(t *testing.T, s *memory.Store, tenantID string, n int) []*checklog.Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := s.ListCheckLogs(context.Background(), &checklog.QueryFilter{TenantID: tenantID, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) >= n {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d check log entries, got %d", n, len(entries))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCheckLog_UncachedEntryPopulatesFields verifies H5: the entry built
// for an uncached Check carries NamespacePath, MatchedBy, RequestID,
// TraceID, and RequestIP, not just the bare decision/reason the
// pre-hardening writer produced.
func TestCheckLog_UncachedEntryPopulatesFields(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}

	ctx := WithTenant(context.Background(), "app1", "t1")
	ctx = WithNamespace(ctx, "eng/platform")
	ctx = log.WithRequestID(ctx, "req-123")
	ctx = log.WithTraceID(ctx, "trace-abc")
	ctx = WithRequestIP(ctx, "203.0.113.7")

	if err := s.CreatePolicy(ctx, &policy.Policy{
		TenantID: "t1", NamespacePath: "eng", Name: "allow-all",
		Effect: policy.EffectAllow, IsActive: true, Actions: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}); err != nil {
		t.Fatal(err)
	}

	entries := drainCheckLogs(t, s, "t1", 1)
	e := entries[0]
	if e.NamespacePath != "eng/platform" {
		t.Errorf("NamespacePath = %q, want %q", e.NamespacePath, "eng/platform")
	}
	if len(e.MatchedBy) == 0 {
		t.Error("expected MatchedBy to be populated")
	}
	if e.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want %q", e.RequestID, "req-123")
	}
	if e.TraceID != "trace-abc" {
		t.Errorf("TraceID = %q, want %q", e.TraceID, "trace-abc")
	}
	if e.RequestIP != "203.0.113.7" {
		t.Errorf("RequestIP = %q, want %q", e.RequestIP, "203.0.113.7")
	}
	if e.Cached {
		t.Error("expected Cached=false for the first (uncached) check")
	}
	if e.Decision != string(DecisionAllow) {
		t.Errorf("Decision = %q, want %q", e.Decision, DecisionAllow)
	}
}

// TestCheckLog_CachedEntryMarksCachedTrue verifies H5: a cache-hit check
// still produces a check log entry, with Cached=true: the pre-hardening
// engine skipped the check log entirely on a cache hit.
func TestCheckLog_CachedEntryMarksCachedTrue(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithConfig(func() Config {
		c := DefaultConfig()
		c.CacheTTL = time.Minute
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	ctx := WithTenant(context.Background(), "app1", "t1")
	if err := s.CreatePolicy(ctx, &policy.Policy{
		TenantID: "t1", Name: "allow-all", Effect: policy.EffectAllow, IsActive: true, Actions: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	if _, err := eng.Check(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Check(ctx, req); err != nil {
		t.Fatal(err)
	}

	entries := drainCheckLogs(t, s, "t1", 2)
	sawCached := false
	for _, e := range entries {
		if e.Cached {
			sawCached = true
		}
	}
	if !sawCached {
		t.Fatal("expected at least one check log entry with Cached=true from the second (cached) Check")
	}
}

// TestCheckLog_HooksFireOnCacheHit verifies H5: OnAfterCheck fires on a
// cache hit, not just the first (uncached) evaluation.
func TestCheckLog_HooksFireOnCacheHit(t *testing.T) {
	s := memory.New()
	cp := &afterCheckCountingPlugin{}
	eng, err := NewEngine(WithStore(s), WithPlugin(cp), WithConfig(func() Config {
		c := DefaultConfig()
		c.CacheTTL = time.Minute
		c.EnableCheckLog = boolPtr(false)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	ctx := WithTenant(context.Background(), "app1", "t1")
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	if _, err := eng.Check(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Check(ctx, req); err != nil {
		t.Fatal(err)
	}

	if cp.count != 2 {
		t.Fatalf("expected OnAfterCheck to fire on both the miss and the hit, got %d calls", cp.count)
	}
}

type afterCheckCountingPlugin struct {
	count int
}

func (p *afterCheckCountingPlugin) Name() string { return "after-check-counter" }
func (p *afterCheckCountingPlugin) OnAfterCheck(_ context.Context, _, _ any) error {
	p.count++
	return nil
}

// TestEngine_StartStop verifies Start/Stop don't error and Stop drains the
// check log writer (a pending entry written just before Stop is still
// flushed).
func TestEngine_StartStop(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx := WithTenant(context.Background(), "app1", "t1")
	if _, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}); err != nil {
		t.Fatal(err)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := eng.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	entries, err := s.ListCheckLogs(context.Background(), &checklog.QueryFilter{TenantID: "t1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected Stop to have flushed the pending entry, got %d entries", len(entries))
	}
}

// TestEngine_FailedEvaluationWritesErrorEntry verifies H5: an evaluation
// error still produces a check log entry with Decision "error" and the
// error message.
func TestEngine_FailedEvaluationWritesErrorEntry(t *testing.T) {
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithEvaluator(erroringEvaluator{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithTenant(context.Background(), "app1", "t1")

	_, err = eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	})
	if err == nil {
		t.Fatal("expected an error from the failing evaluator")
	}

	entries := drainCheckLogs(t, s, "t1", 1)
	if entries[0].Decision != "error" {
		t.Fatalf("expected Decision=error, got %q", entries[0].Decision)
	}
	if entries[0].Error == "" {
		t.Fatal("expected a non-empty Error field")
	}
}

type erroringEvaluator struct{}

func (erroringEvaluator) Evaluate(context.Context, []*policy.Policy, *CheckRequest, []string) (*CheckResult, error) {
	return nil, errEvaluatorBoom
}

var errEvaluatorBoom = evaluatorBoomError{}

type evaluatorBoomError struct{}

func (evaluatorBoomError) Error() string { return "boom" }
