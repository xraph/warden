package contract

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/policy"
)

var fixedNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

// probe runs one condition through warden's real evaluator. It returns the
// outcome as the evaluator sees it: "true", "false" or "throws". It uses
// two policies because each alone is ambiguous: an allow is skipped both
// when its condition is false and when it throws, and a deny applies both
// when its condition is true and when it throws.
func probe(t *testing.T, c policy.Condition, req *warden.CheckRequest) string {
	t.Helper()
	eval := warden.NewConditionEvaluator(func() time.Time { return fixedNow })
	run := func(effect policy.Effect) *warden.CheckResult {
		p := &policy.Policy{Name: "probe", Effect: effect, IsActive: true, Conditions: []policy.Condition{c}}
		res, err := eval.Evaluate(context.Background(), []*policy.Policy{p}, req, nil)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		return res
	}
	allow, deny := run(policy.EffectAllow), run(policy.EffectDeny)
	switch {
	case allow != nil && allow.Allowed:
		return "true"
	case deny != nil:
		return "throws" // deny applied although the allow was skipped
	}
	return "false"
}

// requests covers the ways a check can populate the fields the cases use,
// including values that would make a well-formed version of each condition
// true. A classification that claims a fixed outcome must hold for all.
func requests() []*warden.CheckRequest {
	return []*warden.CheckRequest{
		{Subject: warden.Subject{Kind: "user", ID: "u1"}, Action: warden.Action{Name: "read"}, Resource: warden.Resource{Type: "document", ID: "d1"}},
		{
			Subject:  warden.Subject{Kind: "user", ID: "u2", Attributes: map[string]any{"level": 5, "mfa": true}},
			Action:   warden.Action{Name: "delete"},
			Resource: warden.Resource{Type: "document", ID: "d2", Attributes: map[string]any{"size": 10}},
			Context:  map[string]any{"ip": "10.1.2.3", "at": "2026-06-10T00:00:00Z"},
		},
	}
}

func TestClassifyConditionMatchesTheEvaluator(t *testing.T) {
	cases := []struct {
		name    string
		c       policy.Condition
		problem ConditionProblem
		reason  ConditionReason
	}{
		{"unknown operator throws", policy.Condition{Field: "context.ip", Operator: "approximately", Value: "x"}, ProblemThrows, ReasonUnknownOperator},
		{"uncompilable regex throws", policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: "(unclosed"}, ProblemThrows, ReasonInvalidRegex},
		{"uncompilable regex throws even on an unresolvable field", policy.Condition{Field: "action.verb", Operator: policy.OpRegex, Value: "(unclosed"}, ProblemThrows, ReasonInvalidRegex},
		{"not_in given a string is always true", policy.Condition{Field: "context.ip", Operator: policy.OpNotIn, Value: "10.1.2.3"}, ProblemAlwaysTrue, ReasonNotAList},
		{"in given a string is always false", policy.Condition{Field: "context.ip", Operator: policy.OpIn, Value: "10.1.2.3"}, ProblemAlwaysFalse, ReasonNotAList},
		{"in given an empty list is always false", policy.Condition{Field: "context.ip", Operator: policy.OpIn, Value: []any{}}, ProblemAlwaysFalse, ReasonEmptyList},
		{"not_in given an empty list is always true", policy.Condition{Field: "context.ip", Operator: policy.OpNotIn, Value: []any{}}, ProblemAlwaysTrue, ReasonEmptyList},
		{"gt against a non-number is always false", policy.Condition{Field: "subject.level", Operator: policy.OpGreaterThan, Value: "high"}, ProblemAlwaysFalse, ReasonNotANumber},
		{"ip_in_cidr with no valid CIDR is always false", policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: []any{"10.0.0.0/99", "nope"}}, ProblemAlwaysFalse, ReasonNoValidCIDR},
		{"time_after with an unparseable time is always false", policy.Condition{Field: "context.at", Operator: policy.OpTimeAfter, Value: "last tuesday"}, ProblemAlwaysFalse, ReasonNotATime},
		{"neq on action.verb is always true", policy.Condition{Field: "action.verb", Operator: policy.OpNotEquals, Value: "read"}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"eq on bare action is always false", policy.Condition{Field: "action", Operator: policy.OpEquals, Value: "read"}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"not_exists on an unresolvable field is always true", policy.Condition{Field: "action.verb", Operator: policy.OpNotExists}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"exists on an unresolvable field is always false", policy.Condition{Field: "nodot", Operator: policy.OpExists}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"contains on an unresolvable field compares against <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpContains, Value: "nil"}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"a well-formed ip_in_cidr is not fixed", policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: []any{"10.0.0.0/8"}}, ProblemNone, ReasonNone},
		{"a well-formed in is not fixed", policy.Condition{Field: "context.ip", Operator: policy.OpIn, Value: []any{"10.1.2.3"}}, ProblemNone, ReasonNone},
		{"action.name resolves", policy.Condition{Field: "action.name", Operator: policy.OpEquals, Value: "read"}, ProblemNone, ReasonNone},
		// Beyond the brief: shapes at the edge of each rule, so a rule that is
		// too eager or too shy shows up against the engine.
		{"ip_in_cidr with one good CIDR among bad ones is not fixed", policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: []any{"nope", "10.0.0.0/8"}}, ProblemNone, ReasonNone},
		{"ip_in_cidr given a list-shaped non-string is always false", policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: 7}, ProblemAlwaysFalse, ReasonNoValidCIDR},
		{"gt against a numeric string is not fixed", policy.Condition{Field: "subject.level", Operator: policy.OpGreaterThan, Value: "3"}, ProblemNone, ReasonNone},
		{"gt with no value is always false", policy.Condition{Field: "subject.level", Operator: policy.OpGreaterThan}, ProblemAlwaysFalse, ReasonNotANumber},
		{"time_before with an RFC3339 time is not fixed", policy.Condition{Field: "context.at", Operator: policy.OpTimeBefore, Value: "2026-06-12T00:00:00Z"}, ProblemNone, ReasonNone},
		{"an empty context suffix never resolves", policy.Condition{Field: "context.", Operator: policy.OpExists}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"an uppercase prefix never resolves", policy.Condition{Field: "Subject.id", Operator: policy.OpNotExists}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"regex on an unresolvable field is matched against <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpRegex, Value: "^<nil>$"}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"starts_with on an unresolvable field is matched against <nil>", policy.Condition{Field: "action", Operator: policy.OpStartsWith, Value: "read"}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"in on an unresolvable field looks for <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpIn, Value: []any{"read"}}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"eq with no value on an unresolvable field matches <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpEquals}, ProblemAlwaysTrue, ReasonUnresolvableField},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problem, reason := classifyCondition(tc.c)
			if problem != tc.problem || reason != tc.reason {
				t.Fatalf("classified (%q, %q), want (%q, %q)", problem, reason, tc.problem, tc.reason)
			}
			outcomes := map[string]bool{}
			for i, req := range requests() {
				got := probe(t, tc.c, req)
				outcomes[got] = true
				switch problem {
				case ProblemThrows:
					if got != "throws" {
						t.Errorf("request %d: evaluator says %s, classification says throws", i, got)
					}
				case ProblemAlwaysTrue:
					if got != "true" {
						t.Errorf("request %d: evaluator says %s, classification says always true", i, got)
					}
				case ProblemAlwaysFalse:
					if got != "false" {
						t.Errorf("request %d: evaluator says %s, classification says always false", i, got)
					}
				}
			}
			// A condition classified as not fixed must actually vary across the
			// requests, or the classification is shy about a fixed one.
			if problem == ProblemNone && len(outcomes) < 2 {
				t.Errorf("classified as not fixed, but the evaluator gives one outcome for every request: %v", outcomes)
			}
		})
	}
	// A well-formed condition must actually vary, or the probe is broken.
	c := policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: []any{"10.0.0.0/8"}}
	if probe(t, c, requests()[0]) != "false" || probe(t, c, requests()[1]) != "true" {
		t.Fatal("the probe cannot tell a varying condition from a fixed one")
	}
}

func TestAnalysePolicyIsOrderAware(t *testing.T) {
	throws := policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: "(unclosed"}
	never := policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: "nope"}
	varies := policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: "10.0.0.0/8"}

	cases := []struct {
		name         string
		effect       policy.Effect
		conds        []policy.Condition
		failsClosed  bool
		neverApplies bool
		deciding     int
	}{
		{"a deny whose first condition throws fails closed", policy.EffectDeny, []policy.Condition{throws}, true, false, 0},
		{"an allow whose condition throws never applies", policy.EffectAllow, []policy.Condition{throws}, false, true, 0},
		{"an always-false condition means never applies, for a deny too", policy.EffectDeny, []policy.Condition{never}, false, true, 0},
		{"the first fixed outcome decides: always-false before a throw", policy.EffectDeny, []policy.Condition{never, throws}, false, true, 0},
		{"the first fixed outcome decides: a throw before always-false", policy.EffectDeny, []policy.Condition{throws, never}, true, false, 0},
		{"a varying condition before a throw does not change the classification", policy.EffectDeny, []policy.Condition{varies, throws}, true, false, 1},
		{"an effect that is not exactly allow is a deny", policy.Effect("DENY"), []policy.Condition{throws}, true, false, 0},
		{"a clean policy is neither", policy.EffectDeny, []policy.Condition{varies}, false, false, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := analysePolicy(&policy.Policy{Effect: tc.effect, IsActive: true, Conditions: tc.conds}, fixedNow)
			if a.FailsClosed != tc.failsClosed || a.NeverApplies != tc.neverApplies || a.DecidingCondition != tc.deciding {
				t.Fatalf("got failsClosed=%v neverApplies=%v deciding=%d, want %v %v %d",
					a.FailsClosed, a.NeverApplies, a.DecidingCondition, tc.failsClosed, tc.neverApplies, tc.deciding)
			}
		})
	}
}

func TestAnalysePolicySeesEveryUnrestrictedShape(t *testing.T) {
	for name, p := range map[string]*policy.Policy{
		"empty lists":                        {},
		"an empty subject matcher in a list": {Subjects: []policy.SubjectMatch{{Kind: "user", ID: "u1"}, {}}, Actions: []string{"*"}, Resources: []string{"*"}},
	} {
		t.Run(name, func(t *testing.T) {
			if !analysePolicy(p, fixedNow).MatchesEverything {
				t.Fatal("not recognised as matching every check")
			}
		})
	}
	restricted := &policy.Policy{Subjects: []policy.SubjectMatch{{Kind: "user"}}}
	if analysePolicy(restricted, fixedNow).SubjectsUnrestricted {
		t.Fatal("a kind-only matcher restricts to that kind")
	}
}

func TestPolicyState(t *testing.T) {
	before, after := fixedNow.Add(-time.Hour), fixedNow.Add(time.Hour)
	cases := map[string]struct {
		p    policy.Policy
		want string
	}{
		"inactive wins over the window": {policy.Policy{IsActive: false, NotAfter: &before}, StateInactive},
		"end before start is never":     {policy.Policy{IsActive: true, NotBefore: &after, NotAfter: &before}, StateNever},
		"not started is scheduled":      {policy.Policy{IsActive: true, NotBefore: &after}, StateScheduled},
		"ended is expired":              {policy.Policy{IsActive: true, NotAfter: &before}, StateExpired},
		"inside the window is active":   {policy.Policy{IsActive: true, NotBefore: &before, NotAfter: &after}, StateActive},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := tc.p
			if got := policyState(&p, fixedNow); got != tc.want {
				t.Fatalf("state %q, want %q", got, tc.want)
			}
			// The analysis must agree with the engine's own gate.
			if (policyState(&p, fixedNow) == StateActive) != p.EffectiveAt(fixedNow) {
				t.Fatal("policyState disagrees with EffectiveAt")
			}
		})
	}
}
