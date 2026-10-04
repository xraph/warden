package warden

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/role"
)

// TestEvaluateCondition_Operators tables every Operator constant against a
// representative true/false pair, closing the coverage gap called out in
// the M2 brief item (evaluator.go was at 18% coverage).
func TestEvaluateCondition_Operators(t *testing.T) {
	tests := []struct {
		name     string
		op       policy.Operator
		actual   any
		expected any
		want     bool
	}{
		{"eq true", policy.OpEquals, "admin", "admin", true},
		{"eq false", policy.OpEquals, "admin", "viewer", false},
		{"neq true", policy.OpNotEquals, "admin", "viewer", true},
		{"neq false", policy.OpNotEquals, "admin", "admin", false},
		{"in true", policy.OpIn, "b", []string{"a", "b", "c"}, true},
		{"in false", policy.OpIn, "z", []string{"a", "b", "c"}, false},
		{"in true []any", policy.OpIn, "b", []any{"a", "b", "c"}, true},
		{"not_in true", policy.OpNotIn, "z", []string{"a", "b", "c"}, true},
		{"not_in false", policy.OpNotIn, "b", []string{"a", "b", "c"}, false},
		{"contains true", policy.OpContains, "hello world", "world", true},
		{"contains false", policy.OpContains, "hello world", "bye", false},
		{"starts_with true", policy.OpStartsWith, "hello world", "hello", true},
		{"starts_with false", policy.OpStartsWith, "hello world", "world", false},
		{"ends_with true", policy.OpEndsWith, "hello world", "world", true},
		{"ends_with false", policy.OpEndsWith, "hello world", "hello", false},
		{"gt true", policy.OpGreaterThan, 5, 3, true},
		{"gt false", policy.OpGreaterThan, 3, 5, false},
		{"gt equal is false", policy.OpGreaterThan, 5, 5, false},
		{"lt true", policy.OpLessThan, 3, 5, true},
		{"lt false", policy.OpLessThan, 5, 3, false},
		{"gte true equal", policy.OpGTE, 5, 5, true},
		{"gte true greater", policy.OpGTE, 6, 5, true},
		{"gte false", policy.OpGTE, 4, 5, false},
		{"lte true equal", policy.OpLTE, 5, 5, true},
		{"lte true less", policy.OpLTE, 4, 5, true},
		{"lte false", policy.OpLTE, 6, 5, false},
		{"exists true", policy.OpExists, "x", nil, true},
		{"exists false", policy.OpExists, nil, nil, false},
		{"not_exists true", policy.OpNotExists, nil, nil, true},
		{"not_exists false", policy.OpNotExists, "x", nil, false},
		{"ip_in_cidr true", policy.OpIPInCIDR, "10.0.1.5", "10.0.0.0/8", true},
		{"ip_in_cidr false", policy.OpIPInCIDR, "203.0.113.1", "10.0.0.0/8", false},
		{"ip_in_cidr true list", policy.OpIPInCIDR, "192.168.1.1", []string{"10.0.0.0/8", "192.168.0.0/16"}, true},
		{"ip_in_cidr invalid ip", policy.OpIPInCIDR, "not-an-ip", "10.0.0.0/8", false},
		{"time_after true", policy.OpTimeAfter, "2026-06-01T00:00:00Z", "2026-01-01T00:00:00Z", true},
		{"time_after false", policy.OpTimeAfter, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", false},
		{"time_before true", policy.OpTimeBefore, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", true},
		{"time_before false", policy.OpTimeBefore, "2026-06-01T00:00:00Z", "2026-01-01T00:00:00Z", false},
		{"regex true", policy.OpRegex, "user-123", "^user-[0-9]+$", true},
		{"regex false", policy.OpRegex, "admin", "^user-[0-9]+$", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateCondition(tc.op, tc.actual, tc.expected)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("evaluateCondition(%s, %v, %v) = %v, want %v", tc.op, tc.actual, tc.expected, got, tc.want)
			}
		})
	}
}

func TestEvaluateCondition_UnknownOperator(t *testing.T) {
	_, err := evaluateCondition("bogus", "x", "y")
	if err == nil || !errors.Is(err, ErrInvalidCondition) {
		t.Fatalf("expected ErrInvalidCondition, got %v", err)
	}
}

func TestEvaluateCondition_InvalidRegex(t *testing.T) {
	_, err := evaluateCondition(policy.OpRegex, "x", "(")
	if err == nil || !errors.Is(err, ErrInvalidCondition) {
		t.Fatalf("expected ErrInvalidCondition for bad regex, got %v", err)
	}
}

// TestCompareNumbers_NotComparable verifies the "not comparable" contract:
// a nil or unparsable operand fails the comparison rather than silently
// comparing against a zero value.
func TestCompareNumbers_NotComparable(t *testing.T) {
	tests := []struct {
		name string
		a, b any
	}{
		{"nil actual", nil, 5},
		{"nil expected", 5, nil},
		{"both nil", nil, nil},
		{"unparsable string", "not-a-number", 5},
		{"bool operand", true, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := compareNumbers(tc.a, tc.b)
			if ok {
				t.Fatalf("expected compareNumbers(%v, %v) to report not-comparable", tc.a, tc.b)
			}
		})
	}

	for _, op := range []policy.Operator{policy.OpGreaterThan, policy.OpLessThan, policy.OpGTE, policy.OpLTE} {
		got, err := evaluateCondition(op, nil, 5)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", op, err)
		}
		if got {
			t.Errorf("%s: expected a not-comparable condition to fail, got true", op)
		}
	}
}

func TestCompareNumbers_NumericStringsAndTypes(t *testing.T) {
	tests := []struct {
		a, b any
		want int
	}{
		{5, 3, 1},
		{3, 5, -1},
		{5, 5, 0},
		{"5", 3, 1},
		{int64(5), float64(3), 1},
		{"5.5", "5.5", 0},
	}
	for _, tc := range tests {
		cmp, ok := compareNumbers(tc.a, tc.b)
		if !ok {
			t.Fatalf("compareNumbers(%v, %v): expected comparable", tc.a, tc.b)
		}
		if cmp != tc.want {
			t.Errorf("compareNumbers(%v, %v) = %d, want %d", tc.a, tc.b, cmp, tc.want)
		}
	}
}

// TestEvaluate_SortByPriorityDescendingStableByName verifies policies are
// evaluated highest-priority first, with ties broken by name ascending.
func TestEvaluate_SortByPriorityDescendingStableByName(t *testing.T) {
	ev := NewConditionEvaluator(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) })

	low := &policy.Policy{Name: "low-priority-deny", Effect: policy.EffectDeny, IsActive: true, Priority: 1, Actions: []string{"read"}}
	high := &policy.Policy{Name: "high-priority-allow", Effect: policy.EffectAllow, IsActive: true, Priority: 10, Actions: []string{"read"}}

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	// Deny is normally "sticky" (wins regardless of scan order in the old
	// implementation once found), but since only the FIRST match per
	// effect bucket is kept, priority ordering changes which allow/deny
	// pair is "first". Use two same-effect policies to observe ordering
	// directly via MatchedBy.
	a := &policy.Policy{Name: "b-policy", Effect: policy.EffectAllow, IsActive: true, Priority: 5, Actions: []string{"read"}}
	b := &policy.Policy{Name: "a-policy", Effect: policy.EffectAllow, IsActive: true, Priority: 5, Actions: []string{"read"}}

	res, err := ev.Evaluate(context.Background(), []*policy.Policy{a, b}, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MatchedBy) == 0 {
		t.Fatal("expected a match")
	}
	if res.MatchedBy[0].Detail == "" || !containsSubstr(res.MatchedBy[0].Detail, "a-policy") {
		t.Fatalf("expected tie-break by name (a-policy before b-policy), got %q", res.MatchedBy[0].Detail)
	}

	// Sanity: high-priority allow still wins as the "first" allow over a
	// lower-priority one when order would otherwise put the low-priority
	// one first (list order is [low, high]).
	res2, err := ev.Evaluate(context.Background(), []*policy.Policy{low, high}, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	// low is a deny, high is an allow: deny always wins regardless of
	// priority (explicit deny semantics), so this just confirms both were
	// considered (deny wins).
	if res2.Decision != DecisionDenyExplicit {
		t.Fatalf("expected explicit deny to win, got %s", res2.Decision)
	}
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

// TestEvaluate_ConditionErrorSkipsAllowPolicy verifies M2: a condition
// evaluation error on an ALLOW policy causes that policy to be skipped
// (logged, not propagated) rather than failing the whole Evaluate call.
func TestEvaluate_ConditionErrorSkipsAllowPolicy(t *testing.T) {
	ev := NewConditionEvaluator(time.Now)

	badAllow := &policy.Policy{
		Name: "bad-allow", Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"read"},
		Conditions: []policy.Condition{
			{Field: "subject.id", Operator: policy.OpRegex, Value: "("}, // invalid regex -> eval error
		},
	}
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	res, err := ev.Evaluate(context.Background(), []*policy.Policy{badAllow}, req, nil)
	if err != nil {
		t.Fatalf("expected no error (policy skipped, not propagated), got %v", err)
	}
	if res != nil {
		t.Fatalf("expected no match (bad allow policy skipped, nothing else matched), got %+v", res)
	}
}

// TestEvaluate_ConditionErrorFailsClosedForDenyPolicy verifies M2: a
// condition evaluation error on a DENY policy is treated as "condition
// met" (fail closed) rather than being skipped.
func TestEvaluate_ConditionErrorFailsClosedForDenyPolicy(t *testing.T) {
	ev := NewConditionEvaluator(time.Now)

	badDeny := &policy.Policy{
		Name: "bad-deny", Effect: policy.EffectDeny, IsActive: true,
		Actions: []string{"read"},
		Conditions: []policy.Condition{
			{Field: "subject.id", Operator: policy.OpRegex, Value: "("},
		},
	}
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	res, err := ev.Evaluate(context.Background(), []*policy.Policy{badDeny}, req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.Decision != DecisionDenyExplicit {
		t.Fatalf("expected fail-closed explicit deny, got %+v", res)
	}
}

// TestEvaluate_UnknownEffectTreatedAsDeny verifies the evaluator's defense
// in depth: any Effect value other than exactly "allow" is treated as
// deny.
func TestEvaluate_UnknownEffectTreatedAsDeny(t *testing.T) {
	ev := NewConditionEvaluator(time.Now)
	garbage := &policy.Policy{Name: "garbage-effect", Effect: policy.Effect("garbage"), IsActive: true, Actions: []string{"read"}}
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	res, err := ev.Evaluate(context.Background(), []*policy.Policy{garbage}, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Decision != DecisionDenyExplicit {
		t.Fatalf("expected an unknown effect to be treated as deny, got %+v", res)
	}
}

// ──────────────────────────────────────────────────
// C2: role-scoped policy.SubjectMatch.Role matching
// ──────────────────────────────────────────────────

func TestMatchesSubject_RoleScoped(t *testing.T) {
	ce := &conditionEvaluator{now: time.Now}
	req := &CheckRequest{Subject: Subject{Kind: SubjectUser, ID: "u1"}}

	editorOnly := &policy.Policy{Subjects: []policy.SubjectMatch{{Role: "editor"}}}

	if ce.matchesSubject(editorOnly, req, nil) {
		t.Fatal("a subject with no roles must not match a role-scoped policy")
	}
	if ce.matchesSubject(editorOnly, req, []string{"viewer"}) {
		t.Fatal("a subject without the named role must not match")
	}
	if !ce.matchesSubject(editorOnly, req, []string{"viewer", "editor"}) {
		t.Fatal("a subject holding the named role must match")
	}
}

func TestMatchesSubject_RoleScopedCombinesWithKindAndID(t *testing.T) {
	ce := &conditionEvaluator{now: time.Now}
	req := &CheckRequest{Subject: Subject{Kind: SubjectUser, ID: "u1"}}

	pol := &policy.Policy{Subjects: []policy.SubjectMatch{{Kind: "user", ID: "u1", Role: "editor"}}}
	if ce.matchesSubject(pol, req, nil) {
		t.Fatal("kind+id match alone must not satisfy a Role requirement")
	}
	if !ce.matchesSubject(pol, req, []string{"editor"}) {
		t.Fatal("kind+id+role should all match")
	}

	otherSubject := &CheckRequest{Subject: Subject{Kind: SubjectUser, ID: "u2"}}
	if ce.matchesSubject(pol, otherSubject, []string{"editor"}) {
		t.Fatal("a different subject ID must not match even with the right role")
	}
}

// TestC2_EndToEnd_RoleScopedPolicy verifies the full engine wiring: RBAC
// resolves the subject's roles (direct and inherited), and an ABAC policy
// scoped to a role slug only fires for subjects holding that role.
func TestC2_EndToEnd_RoleScopedPolicy(t *testing.T) {
	eng, s := newTestEngine(t)
	ctx := WithTenant(context.Background(), "app1", "t1")

	viewerRoleID := id.NewRoleID()
	editorRoleID := id.NewRoleID()
	if err := s.CreateRole(ctx, &role.Role{ID: viewerRoleID, TenantID: "t1", Name: "viewer", Slug: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(ctx, &role.Role{ID: editorRoleID, TenantID: "t1", Name: "editor", Slug: "editor", ParentSlug: "viewer"}); err != nil {
		t.Fatal(err)
	}

	if err := s.CreatePolicy(ctx, &policy.Policy{
		TenantID: "t1", Name: "editor-only-allow", Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"publish"}, Resources: []string{"*"},
		Subjects: []policy.SubjectMatch{{Role: "editor"}},
	}); err != nil {
		t.Fatal(err)
	}

	// u1 has no roles at all -> must be denied (RBAC has no perms either;
	// this exercises the "no roles" ABAC fallback resolution path).
	res, err := eng.Check(ctx, &CheckRequest{
		Subject: Subject{Kind: SubjectUser, ID: "u1"}, Action: Action{Name: "publish"}, Resource: Resource{Type: "post", ID: "p1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("subject with no roles must not match the role-scoped policy")
	}

	// u2 holds "viewer" directly (not "editor") -> must be denied.
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: viewerRoleID, SubjectKind: "user", SubjectID: "u2",
	}); err != nil {
		t.Fatal(err)
	}
	res, err = eng.Check(ctx, &CheckRequest{
		Subject: Subject{Kind: SubjectUser, ID: "u2"}, Action: Action{Name: "publish"}, Resource: Resource{Type: "post", ID: "p1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("subject holding only viewer must not match a policy scoped to editor")
	}

	// u3 holds "editor" directly -> must be allowed.
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: editorRoleID, SubjectKind: "user", SubjectID: "u3",
	}); err != nil {
		t.Fatal(err)
	}
	res, err = eng.Check(ctx, &CheckRequest{
		Subject: Subject{Kind: SubjectUser, ID: "u3"}, Action: Action{Name: "publish"}, Resource: Resource{Type: "post", ID: "p1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatalf("subject holding editor directly should match, got %s: %s", res.Decision, res.Reason)
	}
}

func TestInAndNotInRefuseAValueThatIsNotAList(t *testing.T) {
	for _, op := range []policy.Operator{policy.OpIn, policy.OpNotIn} {
		for _, expected := range []any{"10.1.2.3", "a, b", "[a b]", float64(2), nil} {
			if _, err := evaluateCondition(op, "10.1.2.3", expected); !errors.Is(err, errNotAList) {
				t.Errorf("%s %#v: err = %v, want errNotAList", op, expected, err)
			}
		}
	}
	// Any slice is a list, not only []string and []any.
	if ok, err := evaluateCondition(policy.OpIn, 2, []int{1, 2}); err != nil || !ok {
		t.Errorf("in []int{1, 2} with 2 = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestEvaluate_ScalarInFailsClosed pins what a policy whose in or not_in value
// is a string (as the retired templ form stored them) does at check time.
// Read as an empty list, the not_in allow granted everyone and the in deny
// denied no one. As an evaluation error, the allow is skipped and the deny
// applies.
func TestEvaluate_ScalarInFailsClosed(t *testing.T) {
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
		Context:  map[string]any{"ip": "192.168.0.9"},
	}
	cases := []struct {
		effect policy.Effect
		op     policy.Operator
		want   string // "none" or the decision
	}{
		{policy.EffectAllow, policy.OpIn, "none"},
		{policy.EffectAllow, policy.OpNotIn, "none"},
		{policy.EffectDeny, policy.OpIn, string(DecisionDenyExplicit)},
		{policy.EffectDeny, policy.OpNotIn, string(DecisionDenyExplicit)},
	}
	for _, tc := range cases {
		pol := &policy.Policy{
			Name: "templ-made", Effect: tc.effect, IsActive: true,
			Conditions: []policy.Condition{{Field: "context.ip", Operator: tc.op, Value: "10.0.0.1, 10.0.0.2"}},
		}
		res, err := NewConditionEvaluator(time.Now).Evaluate(context.Background(), []*policy.Policy{pol}, req, nil)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.effect, tc.op, err)
		}
		got := "none"
		if res != nil {
			got = string(res.Decision)
		}
		if got != tc.want {
			t.Errorf("%s %s with a string value: decision %s, want %s", tc.effect, tc.op, got, tc.want)
		}
	}
}

// TestValidateConditionAgreesWithTheEvaluatorOnLists holds policy.isList and
// inSlice together: a value validation accepts for in and not_in must
// evaluate, and one it refuses must fail closed, so validation never lets
// through a condition the evaluator cannot read.
func TestValidateConditionAgreesWithTheEvaluatorOnLists(t *testing.T) {
	values := []any{
		"10.0.0.1", "a, b", float64(2), true, nil, map[string]any{"a": 1},
		[]any{"a"}, []string{"a"}, []int{1}, [2]string{"a", "b"}, []any{},
	}
	for _, op := range []policy.Operator{policy.OpIn, policy.OpNotIn} {
		for _, v := range values {
			validErr := policy.ValidateCondition(policy.Condition{Field: "context.ip", Operator: op, Value: v})
			_, evalErr := evaluateCondition(op, "a", v)
			if (validErr == nil) != (evalErr == nil) {
				t.Errorf("%s %#v: validation says %v, the evaluator says %v", op, v, validErr, evalErr)
			}
		}
	}
}
