package warden

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// recordingMetrics is a fake Metrics that records every call, for
// asserting the engine's M1 call sites fire with the right arguments.
type recordingMetrics struct {
	NoopMetrics
	mu     sync.Mutex
	checks []recordedCheck
}

type recordedCheck struct {
	decision Decision
	source   string
	cached   bool
}

func (m *recordingMetrics) CheckEvaluated(decision Decision, source string, _ time.Duration, cached bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks = append(m.checks, recordedCheck{decision: decision, source: source, cached: cached})
}

func (m *recordingMetrics) snapshot() []recordedCheck {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedCheck, len(m.checks))
	copy(out, m.checks)
	return out
}

// TestMetrics_CheckEvaluatedCachedOnHit verifies M1: a recording Metrics
// implementation receives CheckEvaluated with cached=true on a cache hit.
func TestMetrics_CheckEvaluatedCachedOnHit(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	s := memory.New()
	metrics := &recordingMetrics{}

	eng, err := NewEngine(WithStore(s), WithMetrics(metrics), WithConfig(func() Config {
		c := DefaultConfig()
		c.CacheTTL = time.Minute
		c.EnableCheckLog = boolPtr(false)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}
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

	got := metrics.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 CheckEvaluated calls, got %d: %+v", len(got), got)
	}
	if got[0].cached {
		t.Fatalf("expected the first (miss) call to have cached=false, got %+v", got[0])
	}
	if !got[1].cached {
		t.Fatalf("expected the second (hit) call to have cached=true, got %+v", got[1])
	}
	if got[1].decision != DecisionAllow {
		t.Fatalf("expected the cached call to carry the original decision, got %s", got[1].decision)
	}
}
