package dsl

import (
	"context"
	"testing"

	"github.com/xraph/warden"
)

// TestApply_AttributesConditionDecides applies a policy spelled the way the
// DSL reference spells it, subject.attributes.<key>, and checks that the
// condition decides the outcome. It used to resolve to nil, so the allow
// never matched and the deny never fired.
func TestApply_AttributesConditionDecides(t *testing.T) {
	src := `
warden config 1
tenant t1

policy "engineering-reads" {
    effect    = allow
    actions   = ["read"]
    resources = ["document"]
    when {
        subject.attributes.department == "engineering"
    }
}

policy "no-banned-users" {
    effect    = deny
    actions   = ["read"]
    resources = ["document"]
    when {
        subject.attributes.banned exists
    }
}
`
	prog, diags := Parse("test.warden", []byte(src))
	if len(diags) > 0 {
		t.Fatalf("parse: %v", diags)
	}
	eng, _ := newTestEngine(t)
	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	ctx := warden.WithTenant(context.Background(), "", "t1")

	tests := []struct {
		name        string
		attrs       map[string]any
		wantAllowed bool
		wantBanned  bool
	}{
		{"engineering is allowed", map[string]any{"department": "engineering"}, true, false},
		{"sales is not", map[string]any{"department": "sales"}, false, false},
		{"a banned engineer is denied", map[string]any{"department": "engineering", "banned": true}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := eng.Check(ctx, &warden.CheckRequest{
				Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1", Attributes: tt.attrs},
				Action:   warden.Action{Name: "read"},
				Resource: warden.Resource{Type: "document", ID: "d1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Allowed != tt.wantAllowed {
				t.Fatalf("allowed = %v (%s: %s), want %v", res.Allowed, res.Decision, res.Reason, tt.wantAllowed)
			}
			if banned := res.Decision == warden.DecisionDenyExplicit; banned != tt.wantBanned {
				t.Fatalf("decision = %s (%s), explicit deny want %v", res.Decision, res.Reason, tt.wantBanned)
			}
		})
	}
}
