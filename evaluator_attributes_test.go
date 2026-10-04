package warden

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/policy"
)

// The docs, the DSL tests and the editor all spell an attribute condition
// `subject.attributes.<key>`. resolveField used to split only on the first
// dot, so it looked up Attributes["attributes.<key>"] and every such
// condition resolved to nil: an allow never matched and a deny never fired.
func TestEvaluate_AttributesSegmentResolves(t *testing.T) {
	req := &CheckRequest{
		Subject: Subject{Kind: SubjectUser, ID: "u1", Attributes: map[string]any{
			"department": "engineering",
			"team name":  "core",
		}},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1", Attributes: map[string]any{"tier": "gold"}},
	}

	tests := []struct {
		name   string
		effect policy.Effect
		field  string
		value  any
		want   Decision
	}{
		{"allow on subject.attributes.department", policy.EffectAllow, "subject.attributes.department", "engineering", DecisionAllow},
		{"deny on subject.attributes.department", policy.EffectDeny, "subject.attributes.department", "engineering", DecisionDenyExplicit},
		{"allow on resource.attributes.tier", policy.EffectAllow, "resource.attributes.tier", "gold", DecisionAllow},
		{"deny on resource.attributes.tier", policy.EffectDeny, "resource.attributes.tier", "gold", DecisionDenyExplicit},
		{"allow on the bracketed key the DSL emits", policy.EffectAllow, `subject.attributes["team name"]`, "core", DecisionAllow},
		{"the short spelling still works", policy.EffectAllow, "subject.department", "engineering", DecisionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := NewConditionEvaluator(time.Now)
			pol := &policy.Policy{
				Name: "p", Effect: tt.effect, IsActive: true, Actions: []string{"read"},
				Conditions: []policy.Condition{{Field: tt.field, Operator: policy.OpEquals, Value: tt.value}},
			}
			res, err := ev.Evaluate(context.Background(), []*policy.Policy{pol}, req, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res == nil {
				t.Fatalf("%s never matched: the field resolved to nil", tt.field)
			}
			if res.Decision != tt.want {
				t.Fatalf("decision = %s, want %s", res.Decision, tt.want)
			}
		})
	}
}

func TestResolveField_AttributesSegment(t *testing.T) {
	req := &CheckRequest{
		Subject: Subject{Kind: SubjectUser, ID: "u1", Attributes: map[string]any{
			"department":       "engineering",
			"kind":             "contractor",
			"attributes.shard": "literal",
			"shard":            "stripped",
		}},
		Resource: Resource{Type: "doc", ID: "d1", Attributes: map[string]any{"id": "attr-id"}},
	}

	tests := []struct {
		field string
		want  any
	}{
		{"subject.attributes.department", "engineering"},
		{"subject.department", "engineering"},
		// Under attributes., kind and id name the attribute, not the
		// subject's own kind or id.
		{"subject.attributes.kind", "contractor"},
		{"subject.kind", "user"},
		{"resource.attributes.id", "attr-id"},
		{"resource.id", "d1"},
		// A key that really is spelled "attributes.<x>" keeps resolving the
		// way it always did, so no policy that matched before changes.
		{"subject.attributes.shard", "literal"},
		{"subject.attributes.missing", nil},
		{"subject.attributes", nil},
		{`subject.attributes["department"]`, "engineering"},
		{`subject.attributes["unterminated`, nil},
	}
	for _, tt := range tests {
		if got := resolveField(tt.field, req); got != tt.want {
			t.Errorf("resolveField(%q) = %v, want %v", tt.field, got, tt.want)
		}
	}
}
