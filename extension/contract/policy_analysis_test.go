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
		// Values that make the corner cases bite: a newline (the dot does not
		// match it without (?s)), and attributes stored under the name "" (an
		// empty suffix is a real lookup, not a field warden never resolves).
		{
			Subject:  warden.Subject{Kind: "user", ID: "line1\nline2", Attributes: map[string]any{"": "x", "level": "not a number"}},
			Action:   warden.Action{Name: "read"},
			Resource: warden.Resource{Type: "document", ID: "d3", Attributes: map[string]any{"": "y"}},
			Context:  map[string]any{"": "z", "note": "a\nb"},
		},
		// Every always-present field empty: the value is still present, and
		// exists must still be true. The probe has to prove that too.
		{},
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
		{"exists on a context attribute still depends on the check", policy.Condition{Field: "context.ip", Operator: policy.OpExists}, ProblemNone, ReasonNone},
		{"not_exists on a subject attribute still depends on the check", policy.Condition{Field: "subject.level", Operator: policy.OpNotExists}, ProblemNone, ReasonNone},
		{"an empty context suffix is a lookup of the name empty, not fixed", policy.Condition{Field: "context.", Operator: policy.OpExists}, ProblemNone, ReasonNone},
		{"an empty subject suffix is a lookup, not fixed", policy.Condition{Field: "subject.", Operator: policy.OpNotExists}, ProblemNone, ReasonNone},
		{"an empty resource suffix is a lookup, not fixed", policy.Condition{Field: "resource.", Operator: policy.OpExists}, ProblemNone, ReasonNone},
		{"action. with no name never resolves", policy.Condition{Field: "action.", Operator: policy.OpExists}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"contains an empty string is always true", policy.Condition{Field: "subject.id", Operator: policy.OpContains, Value: ""}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"starts_with an empty string is always true", policy.Condition{Field: "context.ip", Operator: policy.OpStartsWith, Value: ""}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"ends_with an empty string is always true", policy.Condition{Field: "resource.id", Operator: policy.OpEndsWith, Value: ""}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"contains a real string is not fixed", policy.Condition{Field: "subject.id", Operator: policy.OpContains, Value: "u"}, ProblemNone, ReasonNone},
		{"regex with the empty pattern is always true", policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: ""}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"regex .* is always true, newline or not", policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: ".*"}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"regex ^.* is always true, newline or not", policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: "^.*"}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"regex .*$ is always true, newline or not", policy.Condition{Field: "context.note", Operator: policy.OpRegex, Value: ".*$"}, ProblemAlwaysTrue, ReasonMatchesAnything},
		{"regex ^.*$ fails on a value with a newline, so it is not fixed", policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: "^.*$"}, ProblemNone, ReasonNone},
		{"gt against NaN is always false", policy.Condition{Field: "subject.level", Operator: policy.OpGreaterThan, Value: "NaN"}, ProblemAlwaysFalse, ReasonNotANumber},
		{"lt against nan in any case is always false", policy.Condition{Field: "subject.level", Operator: policy.OpLessThan, Value: "nan"}, ProblemAlwaysFalse, ReasonNotANumber},
		{"gte against NaN is TRUE for a numeric actual, so not fixed", policy.Condition{Field: "subject.level", Operator: policy.OpGTE, Value: "NaN"}, ProblemNone, ReasonNone},
		{"lte against NaN is TRUE for a numeric actual, so not fixed", policy.Condition{Field: "subject.level", Operator: policy.OpLTE, Value: "NaN"}, ProblemNone, ReasonNone},
		{"lt against +Inf holds for every finite actual, so not fixed", policy.Condition{Field: "subject.level", Operator: policy.OpLessThan, Value: "+Inf"}, ProblemNone, ReasonNone},
		{"gte against -Inf holds for every numeric actual, so not fixed", policy.Condition{Field: "subject.level", Operator: policy.OpGTE, Value: "-Inf"}, ProblemNone, ReasonNone},
		{"an uppercase prefix never resolves", policy.Condition{Field: "Subject.id", Operator: policy.OpNotExists}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"regex on an unresolvable field is matched against <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpRegex, Value: "^<nil>$"}, ProblemAlwaysTrue, ReasonUnresolvableField},
		{"starts_with on an unresolvable field is matched against <nil>", policy.Condition{Field: "action", Operator: policy.OpStartsWith, Value: "read"}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"in on an unresolvable field looks for <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpIn, Value: []any{"read"}}, ProblemAlwaysFalse, ReasonUnresolvableField},
		{"eq with no value on an unresolvable field matches <nil>", policy.Condition{Field: "action.verb", Operator: policy.OpEquals}, ProblemAlwaysTrue, ReasonUnresolvableField},
	}
	// A value each field takes in some requests and not others, so the eq case
	// below really varies.
	alwaysPresent := map[string]string{
		"subject.kind": "user", "subject.id": "u1", "resource.type": "document", "resource.id": "d1", "action.name": "read",
	}
	for _, field := range []string{"subject.kind", "subject.id", "resource.type", "resource.id", "action.name"} {
		cases = append(cases, []struct {
			name    string
			c       policy.Condition
			problem ConditionProblem
			reason  ConditionReason
		}{
			{"exists on " + field + " is always true", policy.Condition{Field: field, Operator: policy.OpExists}, ProblemAlwaysTrue, ReasonAlwaysPresent},
			{"not_exists on " + field + " is always false", policy.Condition{Field: field, Operator: policy.OpNotExists}, ProblemAlwaysFalse, ReasonAlwaysPresent},
			{"eq on " + field + " still depends on the check", policy.Condition{Field: field, Operator: policy.OpEquals, Value: alwaysPresent[field]}, ProblemNone, ReasonNone},
		}...)
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
	absentNever := policy.Condition{Field: "subject.id", Operator: policy.OpNotExists}

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
		{"not_exists on an always-present field means never applies", policy.EffectDeny, []policy.Condition{absentNever}, false, true, 0},
		{"exists on an always-present field restricts nothing and decides nothing", policy.EffectDeny, []policy.Condition{{Field: "subject.id", Operator: policy.OpExists}, varies}, false, false, -1},
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
	now := fixedNow
	cases := map[string]struct {
		p    policy.Policy
		want string
	}{
		"inactive wins over the window":          {policy.Policy{IsActive: false, NotAfter: &before}, StateInactive},
		"end before start is never":              {policy.Policy{IsActive: true, NotBefore: &after, NotAfter: &before}, StateNever},
		"not started is scheduled":               {policy.Policy{IsActive: true, NotBefore: &after}, StateScheduled},
		"ended is expired":                       {policy.Policy{IsActive: true, NotAfter: &before}, StateExpired},
		"inside the window is active":            {policy.Policy{IsActive: true, NotBefore: &before, NotAfter: &after}, StateActive},
		"now equal to the start is active":       {policy.Policy{IsActive: true, NotBefore: &now}, StateActive},
		"now equal to the end is active":         {policy.Policy{IsActive: true, NotAfter: &now}, StateActive},
		"start, end and now all equal is active": {policy.Policy{IsActive: true, NotBefore: &now, NotAfter: &now}, StateActive},
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

// TestUnrestrictedFlagsMatchTheEngine runs a deny scoped by each pattern
// through the real evaluator against varied requests, and requires the
// analysis flag to be set exactly when the policy applies to every one of
// them.
func TestUnrestrictedFlagsMatchTheEngine(t *testing.T) {
	reqs := append(requests(),
		&warden.CheckRequest{Subject: warden.Subject{Kind: "service", ID: "s1"}, Action: warden.Action{Name: "documents.export"}, Resource: warden.Resource{Type: "report", ID: "r9"}},
		&warden.CheckRequest{Subject: warden.Subject{Kind: "user", ID: "u3"}, Action: warden.Action{Name: "*"}, Resource: warden.Resource{Type: "*", ID: "*"}},
		&warden.CheckRequest{Subject: warden.Subject{Kind: "user", ID: "u3"}, Action: warden.Action{Name: ":"}, Resource: warden.Resource{Type: ":", ID: ":"}},
	)
	eval := warden.NewConditionEvaluator(func() time.Time { return fixedNow })
	appliesToAll := func(t *testing.T, p *policy.Policy) bool {
		t.Helper()
		for _, req := range reqs {
			res, err := eval.Evaluate(context.Background(), []*policy.Policy{p}, req, nil)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if res == nil {
				return false
			}
		}
		return true
	}
	cases := []struct {
		pattern      string
		unrestricted bool
	}{
		{"*", true}, {"*:*", true}, {"*.*", true},
		{"document:*", false}, {"documents.*", false}, {"doc*", false}, {"**", false},
		{"", false}, {"*:", false}, {":*", false}, {".*", false}, {"read", false}, {"*:*:*", false},
	}
	for _, tc := range cases {
		for _, kind := range []string{"actions", "resources"} {
			t.Run(kind+" "+tc.pattern, func(t *testing.T) {
				p := &policy.Policy{Effect: policy.EffectDeny, IsActive: true}
				if kind == "actions" {
					p.Actions = []string{tc.pattern}
				} else {
					p.Resources = []string{tc.pattern}
				}
				a := analysePolicy(p, fixedNow)
				flag := a.ActionsUnrestricted
				if kind == "resources" {
					flag = a.ResourcesUnrestricted
				}
				if flag != tc.unrestricted {
					t.Fatalf("flag = %v, want %v", flag, tc.unrestricted)
				}
				if got := appliesToAll(t, p); got != tc.unrestricted {
					t.Fatalf("the engine applies it to every request = %v, the case says %v", got, tc.unrestricted)
				}
				// The other matchers are empty, so the policy matches everything
				// exactly when this pattern does.
				if a.MatchesEverything != tc.unrestricted {
					t.Fatalf("MatchesEverything = %v, want %v", a.MatchesEverything, tc.unrestricted)
				}
			})
		}
	}
}

// TestMatchesEverythingAgreesWithTheEngine runs policies with open matchers
// and assorted condition lists through the real evaluator, as an allow and as
// a deny, and requires the flag to be true exactly when the policy applied to
// every request.
func TestMatchesEverythingAgreesWithTheEngine(t *testing.T) {
	always := policy.Condition{Field: "subject.id", Operator: policy.OpContains, Value: ""}
	alwaysToo := policy.Condition{Field: "action.verb", Operator: policy.OpNotExists}
	present := policy.Condition{Field: "action.name", Operator: policy.OpExists}
	depends := policy.Condition{Field: "subject.level", Operator: policy.OpGreaterThan, Value: float64(1)}
	throws := policy.Condition{Field: "subject.id", Operator: policy.OpRegex, Value: "(unclosed"}
	never := policy.Condition{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: "nope"}

	cases := []struct {
		name  string
		conds []policy.Condition
		// want is the expectation per effect: allow, then deny.
		wantAllow, wantDeny bool
	}{
		{"no conditions", nil, true, true},
		{"all always true", []policy.Condition{always, alwaysToo, present}, true, true},
		{"a request-dependent condition", []policy.Condition{depends}, false, false},
		{"always true, then request-dependent", []policy.Condition{always, depends}, false, false},
		{"request-dependent, then a throw", []policy.Condition{depends, throws}, false, false},
		{"always true, then a throw: a deny fails closed, an allow is skipped", []policy.Condition{always, throws}, false, true},
		{"a throw alone", []policy.Condition{throws}, false, true},
		{"a throw before always-false decides", []policy.Condition{throws, never}, false, true},
		{"always-false first", []policy.Condition{never}, false, false},
		{"always-false before a throw", []policy.Condition{never, throws}, false, false},
		{"always true, then always-false", []policy.Condition{always, never}, false, false},
	}
	eval := warden.NewConditionEvaluator(func() time.Time { return fixedNow })
	sawTrue, sawFalse := false, false
	for _, tc := range cases {
		for _, effect := range []policy.Effect{policy.EffectAllow, policy.EffectDeny, policy.Effect("DENY")} {
			want := tc.wantDeny
			if effect == policy.EffectAllow {
				want = tc.wantAllow
			}
			t.Run(tc.name+"/"+string(effect), func(t *testing.T) {
				p := &policy.Policy{Name: "shape", Effect: effect, IsActive: true, Conditions: tc.conds}
				appliedToAll := true
				for _, req := range requests() {
					res, err := eval.Evaluate(context.Background(), []*policy.Policy{p}, req, nil)
					if err != nil {
						t.Fatalf("Evaluate: %v", err)
					}
					if res == nil {
						appliedToAll = false
					}
				}
				got := analysePolicy(p, fixedNow).MatchesEverything
				if appliedToAll != want {
					t.Fatalf("the engine applied it to every request = %v, the case expects %v", appliedToAll, want)
				}
				if got != appliedToAll {
					t.Fatalf("MatchesEverything = %v, but the engine applied it to every request = %v", got, appliedToAll)
				}
				if got {
					sawTrue = true
				} else {
					sawFalse = true
				}
			})
		}
	}
	if !sawTrue || !sawFalse {
		t.Fatal("the cases never exercised both outcomes")
	}
}

func TestMatchesEverythingIsIndependentOfState(t *testing.T) {
	past := fixedNow.Add(-time.Hour)
	for _, p := range []*policy.Policy{
		{Effect: policy.EffectDeny, IsActive: false},
		{Effect: policy.EffectDeny, IsActive: true, NotAfter: &past},
	} {
		a := analysePolicy(p, fixedNow)
		if a.State == StateActive || !a.MatchesEverything {
			t.Fatalf("state %q, matchesEverything %v: the flag describes the shape, not the state", a.State, a.MatchesEverything)
		}
	}
}
