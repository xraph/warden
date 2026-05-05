package warden

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// TestPolicy_EffectiveAt covers the window edges, nil bounds, and the
// `IsActive=false` short-circuit.
func TestPolicy_EffectiveAt(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		p    policy.Policy
		now  time.Time
		want bool
	}{
		{"inactive overrides window", policy.Policy{IsActive: false, NotBefore: &t1, NotAfter: &t3}, t2, false},
		{"in window", policy.Policy{IsActive: true, NotBefore: &t1, NotAfter: &t3}, t2, true},
		{"before window", policy.Policy{IsActive: true, NotBefore: &t2, NotAfter: &t3}, t1, false},
		{"after window", policy.Policy{IsActive: true, NotBefore: &t1, NotAfter: &t2}, t3, false},
		{"only lower, in", policy.Policy{IsActive: true, NotBefore: &t1}, t2, true},
		{"only lower, out", policy.Policy{IsActive: true, NotBefore: &t2}, t1, false},
		{"only upper, in", policy.Policy{IsActive: true, NotAfter: &t3}, t2, true},
		{"only upper, out", policy.Policy{IsActive: true, NotAfter: &t1}, t2, false},
		{"unbounded", policy.Policy{IsActive: true}, t2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.EffectiveAt(tc.now); got != tc.want {
				t.Errorf("EffectiveAt = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEvaluator_NotBeforeBlocksMatch verifies the evaluator skips a
// policy whose effective window has not opened yet.
func TestEvaluator_NotBeforeBlocksMatch(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	store := memory.New()

	// Policy: deny "delete" on "document" — but only after 2027-01-01.
	notBefore := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	pol := &policy.Policy{
		TenantID:  "t1",
		Name:      "future-deny",
		Effect:    policy.EffectDeny,
		IsActive:  true,
		NotBefore: &notBefore,
		Actions:   []string{"delete"},
		Resources: []string{"document"},
	}
	if err := store.CreatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// Fix the clock at 2026-05-01 — well before the policy opens.
	clock := func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) }
	eng, err := NewEngine(WithStore(store), WithEvaluator(NewConditionEvaluator(clock)))
	if err != nil {
		t.Fatal(err)
	}

	res, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// No RBAC grant; default deny — but the explicit deny must NOT have fired.
	if res.Decision == DecisionDenyExplicit {
		t.Fatalf("explicit deny fired before NotBefore: %+v", res)
	}
}

// TestEvaluator_NotBeforeOpensAt verifies the evaluator activates the
// policy once the clock crosses NotBefore.
func TestEvaluator_NotBeforeOpensAt(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	store := memory.New()

	notBefore := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	pol := &policy.Policy{
		TenantID:  "t1",
		Name:      "future-deny",
		Effect:    policy.EffectDeny,
		IsActive:  true,
		NotBefore: &notBefore,
		Actions:   []string{"delete"},
		Resources: []string{"document"},
	}
	if err := store.CreatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// Fix the clock past the window opens.
	clock := func() time.Time { return time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC) }
	eng, err := NewEngine(WithStore(store), WithEvaluator(NewConditionEvaluator(clock)))
	if err != nil {
		t.Fatal(err)
	}

	res, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != DecisionDenyExplicit {
		t.Fatalf("expected explicit deny once NotBefore opens, got %+v", res)
	}
}

// TestEvaluator_ObligationsCollected verifies that obligations from a
// matched policy surface in CheckResult.Obligations and are deduplicated
// across multiple matched policies.
func TestEvaluator_ObligationsCollected(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	store := memory.New()

	// Two allow policies that both match — different obligations.
	mustCreate := func(p *policy.Policy) {
		if err := store.CreatePolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	mustCreate(&policy.Policy{
		TenantID:    "t1",
		Name:        "allow-with-audit",
		Effect:      policy.EffectAllow,
		IsActive:    true,
		Actions:     []string{"read"},
		Resources:   []string{"document"},
		Obligations: []string{"audit-log"},
	})
	mustCreate(&policy.Policy{
		TenantID:    "t1",
		Name:        "allow-with-mfa",
		Effect:      policy.EffectAllow,
		IsActive:    true,
		Actions:     []string{"read"},
		Resources:   []string{"document"},
		Obligations: []string{"audit-log", "require-mfa"},
	})

	eng, err := NewEngine(WithStore(store))
	if err != nil {
		t.Fatal(err)
	}
	res, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatalf("expected allow, got %+v", res)
	}
	// audit-log appears in both policies — must be deduplicated.
	if len(res.Obligations) != 2 {
		t.Fatalf("expected 2 deduped obligations, got %d: %v", len(res.Obligations), res.Obligations)
	}
	wantSet := map[string]bool{"audit-log": false, "require-mfa": false}
	for _, ob := range res.Obligations {
		if _, ok := wantSet[ob]; !ok {
			t.Errorf("unexpected obligation %q", ob)
		}
		wantSet[ob] = true
	}
	for ob, seen := range wantSet {
		if !seen {
			t.Errorf("missing obligation %q", ob)
		}
	}
}

// obligationCapturePlugin records every obligation the engine fires.
type obligationCapturePlugin struct {
	captured []string
}

func (p *obligationCapturePlugin) Name() string { return "obligation-capture" }
func (p *obligationCapturePlugin) OnPolicyObligationFired(_ context.Context, _ id.PolicyID, ob string, _ any, _ any) error {
	p.captured = append(p.captured, ob)
	return nil
}

// Compile-time interface check.
var _ plugin.PolicyObligationFired = (*obligationCapturePlugin)(nil)

// TestEngine_PolicyObligationFired verifies the plugin hook fires once
// per obligation in the merged result.
func TestEngine_PolicyObligationFired(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	store := memory.New()

	if err := store.CreatePolicy(ctx, &policy.Policy{
		TenantID:    "t1",
		Name:        "audit-everything",
		Effect:      policy.EffectAllow,
		IsActive:    true,
		Actions:     []string{"read"},
		Resources:   []string{"document"},
		Obligations: []string{"audit-log", "notify-security"},
	}); err != nil {
		t.Fatal(err)
	}

	capPlugin := &obligationCapturePlugin{}
	eng, err := NewEngine(WithStore(store), WithPlugin(capPlugin))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
	}); err != nil {
		t.Fatal(err)
	}
	if len(capPlugin.captured) != 2 {
		t.Fatalf("expected 2 obligation events, got %d: %v", len(capPlugin.captured), capPlugin.captured)
	}
}
