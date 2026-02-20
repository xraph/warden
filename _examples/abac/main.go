// Example: attribute-based access control with conditions.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

func main() {
	ctx := warden.WithTenant(context.Background(), "app", "t1")
	s := memory.New()

	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		log.Fatal(err)
	}

	// Allow admins to do anything.
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "admin-allow",
		Effect: policy.EffectAllow, IsActive: true,
		Subjects: []policy.SubjectMatch{{Kind: "user"}},
		Actions:  []string{"*"},
		Conditions: []policy.Condition{
			{Field: "subject.role", Operator: policy.OpEquals, Value: "admin"},
		},
	})

	// Deny access from internal IPs.
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "deny-internal",
		Effect: policy.EffectDeny, IsActive: true,
		Actions: []string{"*"},
		Conditions: []policy.Condition{
			{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: "10.0.0.0/8"},
		},
	})

	// Time-limited access.
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	_ = s.CreatePolicy(ctx, &policy.Policy{
		ID: id.NewPolicyID(), TenantID: "t1", Name: "time-limited",
		Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"read"},
		Conditions: []policy.Condition{
			{Field: "context.time", Operator: policy.OpTimeBefore, Value: future},
		},
	})

	// Admin from external IP — allowed.
	check(eng, ctx, "Admin + external IP",
		warden.Subject{Kind: warden.SubjectUser, ID: "alice", Attributes: map[string]any{"role": "admin"}},
		"delete", "document", "d1",
		map[string]any{"ip": "203.0.113.1"},
	)

	// Admin from internal IP — denied (explicit deny overrides).
	check(eng, ctx, "Admin + internal IP",
		warden.Subject{Kind: warden.SubjectUser, ID: "alice", Attributes: map[string]any{"role": "admin"}},
		"delete", "document", "d1",
		map[string]any{"ip": "10.0.1.5"},
	)

	// Non-admin read within time limit — allowed.
	check(eng, ctx, "Non-admin + time-limited read",
		warden.Subject{Kind: warden.SubjectUser, ID: "bob"},
		"read", "document", "d1",
		map[string]any{"time": time.Now().Format(time.RFC3339)},
	)
}

func check(eng *warden.Engine, ctx context.Context, label string, subject warden.Subject, action, resType, resID string, ctxMap map[string]any) {
	result, err := eng.Check(ctx, &warden.CheckRequest{
		Subject:  subject,
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resType, ID: resID},
		Context:  ctxMap,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[%s] %s → %v (%s)\n", label, action, result.Allowed, result.Decision)
}
