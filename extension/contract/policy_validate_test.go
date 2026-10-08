package contract

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// cleanDraft is a draft nothing objects to. Each test breaks one thing in it.
func cleanDraft() PolicyDraft {
	return PolicyDraft{
		Name:      "office hours",
		Effect:    "allow",
		Subjects:  []PolicySubject{{Kind: "user"}},
		Actions:   []string{"read"},
		Resources: []string{"document:*"},
		Conditions: []PolicyCondition{
			{Field: "context.ip", Operator: "ip_in_cidr", Value: []any{"10.0.0.0/8"}},
		},
		Obligations: []string{"log"},
	}
}

func goodCondition() PolicyCondition {
	return PolicyCondition{Field: "subject.level", Operator: "gte", Value: float64(3)}
}

func TestCollectPolicyIssues_CleanDraftIsValid(t *testing.T) {
	issues := collectPolicyIssues(cleanDraft(), allParts)
	if !issues.empty() {
		t.Fatalf("clean draft has issues: %+v", issues)
	}
	// The page reads these as an object and an array. A nil map or slice would
	// serialise as null and break `issues.fields.name`.
	raw, err := json.Marshal(PolicyValidateResponse{Valid: true, PolicyIssues: issues})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), `{"valid":true,"matchesEverything":false,"fields":{},"conditions":[]}`; got != want {
		t.Fatalf("wire shape %s, want %s", got, want)
	}
}

func TestCollectPolicyIssues_FieldRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PolicyDraft)
		key    string
	}{
		{"a missing name", func(d *PolicyDraft) { d.Name = "" }, "name"},
		{"a blank name", func(d *PolicyDraft) { d.Name = "   " }, "name"},
		{"an effect that is not lower case", func(d *PolicyDraft) { d.Effect = "DENY" }, "effect"},
		{"no effect", func(d *PolicyDraft) { d.Effect = "" }, "effect"},
		{"an end before the start", func(d *PolicyDraft) {
			d.NotBefore, d.NotAfter = "2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z"
		}, "window"},
		{"an end equal to the start", func(d *PolicyDraft) {
			d.NotBefore, d.NotAfter = "2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z"
		}, "window"},
		{"an unparseable start", func(d *PolicyDraft) { d.NotBefore = "next week" }, "window"},
		{"an unparseable end", func(d *PolicyDraft) { d.NotAfter = "2026-06-01" }, "window"},
		{"an empty subject matcher", func(d *PolicyDraft) {
			d.Subjects = []PolicySubject{{Kind: "user"}, {}}
		}, "subjects"},
		{"a subject kind warden does not check", func(d *PolicyDraft) { d.Subjects = []PolicySubject{{Kind: "usr"}} }, "subjects"},
		{"an empty action entry", func(d *PolicyDraft) { d.Actions = []string{"read", ""} }, "actions"},
		{"a blank resource entry", func(d *PolicyDraft) { d.Resources = []string{" "} }, "resources"},
		{"an empty obligation", func(d *PolicyDraft) { d.Obligations = []string{"log", ""} }, "obligations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cleanDraft()
			tc.mutate(&d)
			issues := collectPolicyIssues(d, allParts)
			if issues.empty() {
				t.Fatal("no issue reported")
			}
			if issues.Fields[tc.key] == "" {
				t.Fatalf("no issue under %q: %+v", tc.key, issues.Fields)
			}
			if len(issues.Fields) != 1 || len(issues.Conditions) != 0 {
				t.Fatalf("expected exactly the one issue, got %+v", issues)
			}
		})
	}
}

func TestCollectPolicyIssues_AValidWindowAndKindsPass(t *testing.T) {
	d := cleanDraft()
	d.NotBefore, d.NotAfter = "2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z"
	d.Subjects = []PolicySubject{{Kind: "api_key"}, {Kind: "service"}, {Kind: "service_acct"}, {ID: "u1"}, {Role: "admin"}}
	d.Effect = "deny"
	if issues := collectPolicyIssues(d, allParts); !issues.empty() {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	// Open-ended windows are fine on either side.
	for _, w := range [][2]string{{"2026-06-01T00:00:00Z", ""}, {"", "2026-06-01T00:00:00Z"}} {
		d.NotBefore, d.NotAfter = w[0], w[1]
		if issues := collectPolicyIssues(d, allParts); !issues.empty() {
			t.Fatalf("window %v: unexpected issues: %+v", w, issues)
		}
	}
}

// oneBadConditionPerReason pairs each ConditionReason with a condition that
// produces it and a phrase its message must carry, so a reason cannot slip
// through with another reason's wording.
var oneBadConditionPerReason = []struct {
	reason ConditionReason
	c      PolicyCondition
	says   string
}{
	{ReasonUnknownOperator, PolicyCondition{Field: "context.ip", Operator: "approximately", Value: "x"}, "not an operator warden knows"},
	{ReasonInvalidRegex, PolicyCondition{Field: "subject.id", Operator: "regex", Value: "(unclosed"}, "does not compile"},
	{ReasonUnresolvableField, PolicyCondition{Field: "action.verb", Operator: "neq", Value: "read"}, "never gives"},
	{ReasonMatchesAnything, PolicyCondition{Field: "subject.id", Operator: "contains", Value: ""}, "matches every value"},
	{ReasonAlwaysPresent, PolicyCondition{Field: "action.name", Operator: "not_exists"}, "always gives"},
	{ReasonNotAList, PolicyCondition{Field: "context.ip", Operator: "not_in", Value: "10.1.2.3"}, "needs a list"},
	{ReasonEmptyList, PolicyCondition{Field: "context.ip", Operator: "in", Value: []any{}}, "list is empty"},
	{ReasonNotANumber, PolicyCondition{Field: "subject.level", Operator: "gt", Value: "high"}, "compares numbers"},
	{ReasonNoValidCIDR, PolicyCondition{Field: "context.ip", Operator: "ip_in_cidr", Value: []any{"10.0.0.0/99"}}, "None of these parse"},
	{ReasonNotATime, PolicyCondition{Field: "context.at", Operator: "time_after", Value: "last tuesday"}, "RFC3339"},
}

func TestCollectPolicyIssues_OneConditionPerReason(t *testing.T) {
	for _, tc := range oneBadConditionPerReason {
		t.Run(string(tc.reason), func(t *testing.T) {
			// The row under test is at index 2 of three, so an index that is
			// accidentally always 0 (or always the last) cannot pass.
			d := cleanDraft()
			d.Conditions = []PolicyCondition{goodCondition(), goodCondition(), tc.c}
			if _, reason := classifyCondition(policy.Condition{Field: tc.c.Field, Operator: policy.Operator(tc.c.Operator), Value: tc.c.Value}); reason != tc.reason {
				t.Fatalf("the fixture classifies as %q, not %q", reason, tc.reason)
			}
			issues := collectPolicyIssues(d, allParts)
			if len(issues.Fields) != 0 {
				t.Fatalf("unexpected field issues: %+v", issues.Fields)
			}
			if len(issues.Conditions) != 1 || issues.Conditions[0].Index != 2 {
				t.Fatalf("want one issue at index 2, got %+v", issues.Conditions)
			}
			if msg := issues.Conditions[0].Message; !strings.Contains(msg, tc.says) {
				t.Fatalf("message %q does not say %q", msg, tc.says)
			}
		})
	}
}

func TestCollectPolicyIssues_IndexFollowsThePositionSent(t *testing.T) {
	bad := oneBadConditionPerReason[3].c
	for pos := 0; pos < 3; pos++ {
		d := cleanDraft()
		d.Conditions = []PolicyCondition{goodCondition(), goodCondition(), goodCondition()}
		d.Conditions[pos] = bad
		issues := collectPolicyIssues(d, allParts)
		if len(issues.Conditions) != 1 || issues.Conditions[0].Index != pos {
			t.Fatalf("bad row at %d reported as %+v", pos, issues.Conditions)
		}
	}
}

func TestCollectPolicyIssues_ReportsEveryBadRowInOnePass(t *testing.T) {
	d := cleanDraft()
	d.Conditions = []PolicyCondition{
		oneBadConditionPerReason[0].c, // 0 bad
		goodCondition(),               // 1 fine
		oneBadConditionPerReason[5].c, // 2 bad
		oneBadConditionPerReason[7].c, // 3 bad
		goodCondition(),               // 4 fine
		oneBadConditionPerReason[1].c, // 5 bad
	}
	d.Name = "" // field issues arrive in the same pass as row issues
	issues := collectPolicyIssues(d, allParts)
	got := make([]int, 0, len(issues.Conditions))
	for _, ci := range issues.Conditions {
		got = append(got, ci.Index)
	}
	want := []int{0, 2, 3, 5}
	if len(got) != len(want) {
		t.Fatalf("bad rows reported at %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bad rows reported at %v, want %v", got, want)
		}
	}
	if issues.Fields["name"] == "" {
		t.Fatalf("the name issue was dropped: %+v", issues.Fields)
	}
}

func TestCollectPolicyIssues_TheRegexLengthCapIsPolicyValidatesNotTheAnalysis(t *testing.T) {
	long := strings.Repeat("a", 513)
	c := PolicyCondition{Field: "subject.id", Operator: "regex", Value: long}
	pc := policy.Condition{Field: c.Field, Operator: policy.OpRegex, Value: c.Value}
	if problem, _ := classifyCondition(pc); problem != ProblemNone {
		t.Fatalf("the analysis flagged a compiling regex: %q", problem)
	}
	d := cleanDraft()
	d.Conditions = []PolicyCondition{goodCondition(), c}
	issues := collectPolicyIssues(d, allParts)
	if len(issues.Conditions) != 1 || issues.Conditions[0].Index != 1 {
		t.Fatalf("want one issue at index 1, got %+v", issues.Conditions)
	}
	if !strings.Contains(issues.Conditions[0].Message, "512") {
		t.Fatalf("message %q does not name the cap", issues.Conditions[0].Message)
	}
	// Exactly at the cap is fine.
	d.Conditions[1].Value = strings.Repeat("a", 512)
	if issues := collectPolicyIssues(d, allParts); !issues.empty() {
		t.Fatalf("a 512 character pattern was refused: %+v", issues)
	}
}

func TestCollectPolicyIssues_NumbersPastExactFloat64Range(t *testing.T) {
	cases := map[string]PolicyCondition{
		"gt":            {Field: "subject.level", Operator: "gt", Value: 1e16},
		"gt negative":   {Field: "subject.level", Operator: "lt", Value: -1e16},
		"inside an in":  {Field: "subject.level", Operator: "in", Value: []any{"a", 1e16}},
		"eq":            {Field: "subject.level", Operator: "eq", Value: 1e16},
		"in via string": {Field: "subject.level", Operator: "in", Value: []any{float64(1 << 60)}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := cleanDraft()
			d.Conditions = []PolicyCondition{goodCondition(), c}
			issues := collectPolicyIssues(d, allParts)
			if len(issues.Conditions) != 1 || issues.Conditions[0].Index != 1 {
				t.Fatalf("want one issue at index 1, got %+v", issues.Conditions)
			}
			if !strings.Contains(issues.Conditions[0].Message, "precision") {
				t.Fatalf("message %q does not explain the precision loss", issues.Conditions[0].Message)
			}
		})
	}
	// The boundary itself is exact.
	d := cleanDraft()
	d.Conditions = []PolicyCondition{{Field: "subject.level", Operator: "gt", Value: float64(maxExactInteger)}}
	if issues := collectPolicyIssues(d, allParts); !issues.empty() {
		t.Fatalf("2^53 was refused: %+v", issues)
	}
}

func TestCollectPolicyIssues_APartialDraftValidatesOnlyWhatItChanges(t *testing.T) {
	// A policy stored before validation existed can carry a bad condition and
	// a bad window. Editing its description must still go through.
	stale := cleanDraft()
	stale.Conditions = []PolicyCondition{oneBadConditionPerReason[0].c}
	stale.NotBefore, stale.NotAfter = "2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z"
	stale.Subjects = []PolicySubject{{}}
	stale.Actions = []string{""}
	stale.Name = ""

	// Sanity: the whole thing is refused when everything is validated.
	full := collectPolicyIssues(stale, allParts)
	if len(full.Conditions) != 1 || len(full.Fields) != 4 {
		t.Fatalf("the stale draft should fail everywhere under allParts: %+v", full)
	}

	if issues := collectPolicyIssues(stale, draftParts{}); !issues.empty() {
		t.Fatalf("a description-only change was refused over stored problems: %+v", issues)
	}

	// Each part is gated by its own flag and by no other.
	one := map[string]draftParts{
		"name":       {name: true},
		"window":     {window: true},
		"subjects":   {subjects: true},
		"actions":    {actions: true},
		"conditions": {conditions: true},
	}
	for part, parts := range one {
		issues := collectPolicyIssues(stale, parts)
		if part == "conditions" {
			if len(issues.Conditions) != 1 || len(issues.Fields) != 0 {
				t.Fatalf("conditions only: %+v", issues)
			}
			continue
		}
		if issues.Fields[part] == "" || len(issues.Fields) != 1 || len(issues.Conditions) != 0 {
			t.Fatalf("%s only: %+v", part, issues)
		}
	}
	bad := cleanDraft()
	bad.Effect, bad.Resources, bad.Obligations = "DENY", []string{""}, []string{""}
	for part, parts := range map[string]draftParts{
		"effect": {effect: true}, "resources": {resources: true}, "obligations": {obligations: true},
	} {
		issues := collectPolicyIssues(bad, parts)
		if issues.Fields[part] == "" || len(issues.Fields) != 1 {
			t.Fatalf("%s only: %+v", part, issues)
		}
	}
}

func TestIssuesError(t *testing.T) {
	if err := issuesError(PolicyIssues{Fields: map[string]string{}, Conditions: []ConditionIssue{}}); err != nil {
		t.Fatalf("empty issues produced %v", err)
	}
	d := cleanDraft()
	d.Name = ""
	d.Conditions = []PolicyCondition{goodCondition(), oneBadConditionPerReason[2].c}
	err := issuesError(collectPolicyIssues(d, allParts))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if !strings.Contains(ce.Message, "1 condition(s) and 1 field(s)") {
		t.Fatalf("message %q does not count the issues", ce.Message)
	}
	fields, ok := ce.Details["fields"].(map[string]string)
	if !ok || fields["name"] == "" {
		t.Fatalf("details carry no field issues: %+v", ce.Details)
	}
	conds, ok := ce.Details["conditions"].([]ConditionIssue)
	if !ok || len(conds) != 1 || conds[0].Index != 1 {
		t.Fatalf("details carry no row issues: %+v", ce.Details)
	}
}

func TestToPolicyConditions(t *testing.T) {
	keep := id.NewConditionID()
	out := toPolicyConditions([]PolicyCondition{
		{ID: keep.String(), Field: "  subject.id ", Operator: "eq", Value: "u1"},
		{Field: "context.ip", Operator: "in", Value: []any{"a"}},
		{ID: "not-an-id", Field: "context.ip", Operator: "exists"},
		{ID: id.NewRoleID().String(), Field: "context.ip", Operator: "exists"}, // wrong prefix
	}, []policy.Condition{{ID: keep}})
	if len(out) != 4 {
		t.Fatalf("got %d conditions", len(out))
	}
	if out[0].ID != keep {
		t.Fatalf("a sent id that belongs to a stored condition was replaced: %v", out[0].ID)
	}
	if out[0].Field != "subject.id" || out[0].Operator != policy.OpEquals {
		t.Fatalf("field or operator not carried: %+v", out[0])
	}
	seen := map[string]bool{keep.String(): true}
	for i, c := range out[1:] {
		if c.ID.String() == "" || seen[c.ID.String()] {
			t.Fatalf("condition %d has a blank or repeated id: %v", i+1, c.ID)
		}
		seen[c.ID.String()] = true
	}
	if out[1].Value == nil {
		t.Fatal("value dropped")
	}
	if got := toPolicyConditions(nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("nil in must give an empty, non-nil slice, got %#v", got)
	}
}

func TestPolicyDraftDecodesTheCamelCaseWire(t *testing.T) {
	const wire = `{
		"name": "n", "effect": "deny", "priority": 5,
		"notBefore": "2026-06-01T00:00:00Z", "notAfter": "2026-06-02T00:00:00Z",
		"subjects": [{"kind": "user", "role": "admin"}],
		"actions": ["read"], "resources": ["doc:*"],
		"conditions": [{"field": "subject.level", "operator": "gt", "value": 1e16}],
		"obligations": ["log"]
	}`
	var d PolicyDraft
	if err := json.Unmarshal([]byte(wire), &d); err != nil {
		t.Fatal(err)
	}
	if d.NotBefore == "" || d.NotAfter == "" || d.Priority != 5 || d.Subjects[0].Role != "admin" {
		t.Fatalf("decoded wrong: %+v", d)
	}
	issues := collectPolicyIssues(d, allParts)
	if len(issues.Conditions) != 1 || len(issues.Fields) != 0 {
		t.Fatalf("a JSON 1e16 must decode to float64 and be refused: %+v", issues)
	}
}

func TestPoliciesValidateHandler(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	ctx := context.Background()

	t.Run("reports a bad draft without an error", func(t *testing.T) {
		d := cleanDraft()
		d.Conditions = []PolicyCondition{goodCondition(), goodCondition(), oneBadConditionPerReason[4].c}
		res, err := policiesValidateHandler(Deps{Engine: eng})(ctx, d, principalFor("t1"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid || len(res.Conditions) != 1 || res.Conditions[0].Index != 2 {
			t.Fatalf("got %+v", res)
		}
	})
	t.Run("a clean draft is valid", func(t *testing.T) {
		res, err := policiesValidateHandler(Deps{Engine: eng})(ctx, cleanDraft(), principalFor("t1"))
		if err != nil || !res.Valid {
			t.Fatalf("got %+v, %v", res, err)
		}
	})
	t.Run("validates every part, as a create would", func(t *testing.T) {
		res, err := policiesValidateHandler(Deps{Engine: eng})(ctx, PolicyDraft{}, principalFor("t1"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid || res.Fields["name"] == "" || res.Fields["effect"] == "" {
			t.Fatalf("an empty draft passed: %+v", res)
		}
	})
	t.Run("needs an engine", func(t *testing.T) {
		if _, err := policiesValidateHandler(Deps{})(ctx, cleanDraft(), principalFor("t1")); err == nil {
			t.Fatal("no engine, no error")
		}
	})
	t.Run("needs a tenant", func(t *testing.T) {
		if _, err := policiesValidateHandler(Deps{Engine: eng})(ctx, cleanDraft(), signedInNoTenant()); err == nil {
			t.Fatal("no tenant, no error")
		}
	})
}

// conditionMessage returns the one message conditionIssue gives c, failing
// the test if it gives none.
func conditionMessage(t *testing.T, c PolicyCondition) string {
	t.Helper()
	msg := conditionIssue(c)
	if msg == "" {
		t.Fatalf("%+v was accepted", c)
	}
	return msg
}

func TestConditionIssue_ValidatesExactlyWhatIsStored(t *testing.T) {
	// A padded field that does not resolve is refused, and it is refused for
	// the field that would be STORED, not the padded string.
	msg := conditionMessage(t, PolicyCondition{Field: "  action.verb ", Operator: "neq", Value: "read"})
	if !strings.Contains(msg, `"action.verb"`) || strings.Contains(msg, "  action") {
		t.Fatalf("message %q should quote the trimmed field", msg)
	}

	// Trailing space, always-present field, not_exists: storage trims it to
	// subject.id, so it is a dead policy. It must be refused, not stored.
	msg = conditionMessage(t, PolicyCondition{Field: "subject.id ", Operator: "not_exists"})
	if !strings.Contains(msg, "always gives") || !strings.Contains(msg, "always be false") {
		t.Fatalf("message %q", msg)
	}

	// A working field with padding is accepted, and stored trimmed.
	good := PolicyCondition{Field: " action.name ", Operator: "eq", Value: "read"}
	if msg := conditionIssue(good); msg != "" {
		t.Fatalf("a padded action.name was refused: %q", msg)
	}
	stored := toPolicyConditions([]PolicyCondition{good}, nil)
	if stored[0].Field != "action.name" {
		t.Fatalf("stored %q", stored[0].Field)
	}

	// The invariant itself: whatever is accepted classifies the same after
	// storage as it was validated.
	for _, c := range []PolicyCondition{good, {Field: "context.ip\t", Operator: "exists"}, {Field: "\nsubject.level", Operator: "gt", Value: float64(2)}} {
		validated, _ := classifyCondition(storedCondition(c))
		s := toPolicyConditions([]PolicyCondition{c}, nil)[0]
		again, _ := classifyCondition(policy.Condition{Field: s.Field, Operator: s.Operator, Value: s.Value})
		if validated != again || conditionIssue(c) != "" {
			t.Fatalf("%+v: validated %q, stored %q, issue %q", c, validated, again, conditionIssue(c))
		}
	}
}

func TestConditionIssue_EmptyListMessagesSayWhatTheConditionDoes(t *testing.T) {
	in := conditionMessage(t, PolicyCondition{Field: "context.ip", Operator: "in", Value: []any{}})
	if want := "The list is empty, so this condition is never met and the policy never applies."; in != want {
		t.Fatalf("in [] says %q, want %q", in, want)
	}
	notIn := conditionMessage(t, PolicyCondition{Field: "context.ip", Operator: "not_in", Value: []any{}})
	if want := "The list is empty, so this condition restricts nothing."; notIn != want {
		t.Fatalf("not_in [] says %q, want %q", notIn, want)
	}
}

func TestConditionIssue_NonFiniteNumbers(t *testing.T) {
	const want = "The value is not a finite number."
	for _, op := range []string{"gt", "lt", "gte", "lte"} {
		for _, v := range []any{"NaN", "nan", "+Inf", "-Inf", "Infinity", "inf"} {
			if got := conditionMessage(t, PolicyCondition{Field: "subject.level", Operator: op, Value: v}); got != want {
				t.Errorf("%s %v: %q, want %q", op, v, got, want)
			}
		}
	}
	// A finite number in either form is fine.
	for _, v := range []any{float64(3), "3", "-2.5", "1e3"} {
		if msg := conditionIssue(PolicyCondition{Field: "subject.level", Operator: "lt", Value: v}); msg != "" {
			t.Errorf("lt %v refused: %q", v, msg)
		}
	}
}

func TestConditionIssue_MatchesEverything(t *testing.T) {
	const want = "This matches every value, so this condition is always true and restricts nothing."
	for _, c := range []PolicyCondition{
		{Field: "subject.id", Operator: "contains", Value: ""},
		{Field: "subject.id", Operator: "starts_with", Value: ""},
		{Field: "subject.id", Operator: "ends_with", Value: ""},
		{Field: "subject.id", Operator: "regex", Value: ".*"},
		{Field: "subject.id", Operator: "regex", Value: ""},
	} {
		if got := conditionMessage(t, c); got != want {
			t.Errorf("%+v: %q, want %q", c, got, want)
		}
	}
	// ^.*$ fails on a value with a newline, so it restricts and is allowed.
	if msg := conditionIssue(PolicyCondition{Field: "subject.id", Operator: "regex", Value: "^.*$"}); msg != "" {
		t.Errorf("^.*$ refused: %q", msg)
	}
}

func TestConditionIssue_PrecisionMessageFollowsTheOperator(t *testing.T) {
	const asString = "Numbers above 9007199254740992 lose precision when stored. Store it as a string instead."
	const smaller = "Numbers above 9007199254740992 lose precision when stored, and a comparison reads a string as a number too, so use a smaller number."
	for _, op := range []string{"eq", "neq", "in", "not_in"} {
		var v any = 1e16
		if op == "in" || op == "not_in" {
			v = []any{1e16}
		}
		if got := conditionMessage(t, PolicyCondition{Field: "subject.level", Operator: op, Value: v}); got != asString {
			t.Errorf("%s: %q, want %q", op, got, asString)
		}
	}
	for _, op := range []string{"gt", "lt", "gte", "lte"} {
		if got := conditionMessage(t, PolicyCondition{Field: "subject.level", Operator: op, Value: 1e16}); got != smaller {
			t.Errorf("%s: %q, want %q", op, got, smaller)
		}
	}
}

func TestWindowIssue_EndEqualToStartSaysOnlyWhatIsTrue(t *testing.T) {
	// EffectiveAt holds at exactly that instant, so "never in effect" would be
	// false. It is still refused: a one-instant window is not a schedule.
	const want = "The end must be after the start."
	got := windowIssue("2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z")
	if got != want {
		t.Fatalf("equal window says %q, want %q", got, want)
	}
	if got := windowIssue("2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z"); got != want {
		t.Fatalf("reversed window says %q, want %q", got, want)
	}
}

func TestPoliciesValidateReportsMatchesEverything(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	h := policiesValidateHandler(Deps{Engine: eng})
	call := func(d PolicyDraft) PolicyValidateResponse {
		t.Helper()
		res, err := h(context.Background(), d, principalFor("t1"))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	open := PolicyDraft{Name: "open", Effect: "deny", Subjects: []PolicySubject{}, Actions: []string{"*"}, Resources: []string{" *:* "}}

	if res := call(open); !res.MatchesEverything || !res.Valid {
		t.Fatalf("an open deny with no conditions: %+v", res)
	}
	withDept := open
	withDept.Conditions = []PolicyCondition{{Field: "subject.dept", Operator: "eq", Value: "eng"}}
	if res := call(withDept); res.MatchesEverything {
		t.Fatalf("a request-dependent condition still matches everything: %+v", res)
	}
	restricted := open
	restricted.Actions = []string{"read"}
	if res := call(restricted); res.MatchesEverything {
		t.Fatalf("a restricted action matches everything: %+v", res)
	}
	// An always-true condition changes nothing, and is also refused: the
	// answer is about the shape, whatever else the draft has wrong.
	trivial := open
	trivial.Conditions = []PolicyCondition{{Field: "subject.id", Operator: "contains", Value: ""}}
	if res := call(trivial); !res.MatchesEverything || res.Valid {
		t.Fatalf("an always-true condition: %+v", res)
	}
	// The same analysis the list uses, given the draft as it would be stored.
	shape := &policy.Policy{Effect: policy.EffectDeny, Actions: []string{"*"}, Resources: []string{"*:*"}}
	if got := analysePolicy(shape, fixedNow).MatchesEverything; !got {
		t.Fatal("the stored shape does not match everything")
	}
}
