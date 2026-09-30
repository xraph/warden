package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedPolicyFor stores one policy for tenant, applying tweak (may be nil) to
// a baseline active allow before it is written.
func seedPolicyFor(t *testing.T, s *memory.Store, tenant, namespace, name string, tweak func(*policy.Policy)) *policy.Policy {
	t.Helper()
	p := &policy.Policy{
		TenantID:      tenant,
		NamespacePath: namespace,
		Name:          name,
		Effect:        policy.EffectAllow,
		IsActive:      true,
		Version:       1,
	}
	if tweak != nil {
		tweak(p)
	}
	if err := s.CreatePolicy(context.Background(), p); err != nil {
		t.Fatalf("create policy %q: %v", name, err)
	}
	return p
}

func seedPolicy(t *testing.T, s *memory.Store, namespace, name string, tweak func(*policy.Policy)) *policy.Policy {
	t.Helper()
	return seedPolicyFor(t, s, "t1", namespace, name, tweak)
}

func policyNames(items []PolicySummary) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Name)
	}
	return out
}

func sorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func TestPoliciesListPagesThroughEveryRow(t *testing.T) {
	s := memory.New()
	// Priority is the store's order, so the pages are deterministic.
	for i := 1; i <= 5; i++ {
		i := i
		seedPolicy(t, s, "", fmt.Sprintf("p%d", i), func(p *policy.Policy) { p.Priority = i })
	}
	h := policiesListHandler(Deps{Engine: engineOver(t, s)})

	var seen []string
	for _, tc := range []struct {
		offset int
		want   []string
	}{
		{0, []string{"p1", "p2"}},
		{2, []string{"p3", "p4"}},
		{4, []string{"p5"}},
		{6, []string{}},
	} {
		got, err := h(context.Background(), PoliciesListInput{PageRequest: PageRequest{Limit: 2, Offset: tc.offset}}, principalFor("t1"))
		if err != nil {
			t.Fatalf("offset %d: %v", tc.offset, err)
		}
		if got.Total != 5 {
			t.Errorf("offset %d: total = %d, want 5 on every page", tc.offset, got.Total)
		}
		if got.Limit != 2 || got.Offset != tc.offset {
			t.Errorf("offset %d: echoed limit/offset = %d/%d, want 2/%d", tc.offset, got.Limit, got.Offset, tc.offset)
		}
		if names := policyNames(got.Items); !reflect.DeepEqual(names, tc.want) {
			t.Errorf("offset %d: items = %v, want %v", tc.offset, names, tc.want)
		}
		seen = append(seen, policyNames(got.Items)...)
	}
	if want := []string{"p1", "p2", "p3", "p4", "p5"}; !reflect.DeepEqual(seen, want) {
		t.Errorf("paging visited %v, want %v: a row was skipped or repeated", seen, want)
	}
}

func TestPoliciesListWithNoLimitDoesNotReturnEverything(t *testing.T) {
	s := memory.New()
	for i := 0; i < defaultPageLimit+3; i++ {
		seedPolicy(t, s, "", fmt.Sprintf("p%02d", i), nil)
	}
	h := policiesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PoliciesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.list: %v", err)
	}
	if len(got.Items) != defaultPageLimit {
		t.Errorf("no limit returned %d rows, want the default page of %d", len(got.Items), defaultPageLimit)
	}
	if got.Total != int64(defaultPageLimit+3) {
		t.Errorf("total = %d, want %d", got.Total, defaultPageLimit+3)
	}
}

func TestPoliciesListEveryFilterReachesTheStoreAndTheCount(t *testing.T) {
	s := memory.New()
	seedPolicy(t, s, "", "root-allow", nil)
	seedPolicy(t, s, "", "root-deny", func(p *policy.Policy) { p.Effect = policy.EffectDeny; p.IsActive = false })
	seedPolicy(t, s, "eng", "eng-allow", nil)
	seedPolicy(t, s, "eng", "eng-deny-payments", func(p *policy.Policy) { p.Effect = policy.EffectDeny })
	seedPolicy(t, s, "eng", "eng-allow-old", func(p *policy.Policy) { p.IsActive = false })
	h := policiesListHandler(Deps{Engine: engineOver(t, s)})

	for _, tc := range []struct {
		name string
		in   PoliciesListInput
		want []string
	}{
		{"no filter is every namespace", PoliciesListInput{}, []string{"eng-allow", "eng-allow-old", "eng-deny-payments", "root-allow", "root-deny"}},
		{"empty namespace is the root only", PoliciesListInput{NamespacePath: strPtr("")}, []string{"root-allow", "root-deny"}},
		{"a namespace path", PoliciesListInput{NamespacePath: strPtr("eng")}, []string{"eng-allow", "eng-allow-old", "eng-deny-payments"}},
		{"effect deny", PoliciesListInput{Effect: "deny"}, []string{"eng-deny-payments", "root-deny"}},
		{"effect allow", PoliciesListInput{Effect: "allow"}, []string{"eng-allow", "eng-allow-old", "root-allow"}},
		{"active only", PoliciesListInput{IsActive: boolPtr(true)}, []string{"eng-allow", "eng-deny-payments", "root-allow"}},
		{"inactive only", PoliciesListInput{IsActive: boolPtr(false)}, []string{"eng-allow-old", "root-deny"}},
		{"search", PoliciesListInput{Search: "payments"}, []string{"eng-deny-payments"}},
		{"search ignores case", PoliciesListInput{Search: "PAYMENTS"}, []string{"eng-deny-payments"}},
		{"search with no match", PoliciesListInput{Search: "nothing-is-called-this"}, []string{}},
		{"filters combine", PoliciesListInput{NamespacePath: strPtr("eng"), Effect: "allow", IsActive: boolPtr(true)}, []string{"eng-allow"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := h(context.Background(), tc.in, principalFor("t1"))
			if err != nil {
				t.Fatalf("policies.list: %v", err)
			}
			if names := sorted(policyNames(got.Items)); !reflect.DeepEqual(names, tc.want) {
				t.Errorf("items = %v, want %v", names, tc.want)
			}
			if got.Total != int64(len(tc.want)) {
				t.Errorf("total = %d, want %d: the count did not honour the same filter as the page", got.Total, len(tc.want))
			}

			// The same filter with a one-row page: the page shrinks, the
			// total does not.
			in := tc.in
			in.Limit = 1
			one, err := h(context.Background(), in, principalFor("t1"))
			if err != nil {
				t.Fatalf("policies.list (limit 1): %v", err)
			}
			wantItems := len(tc.want)
			if wantItems > 1 {
				wantItems = 1
			}
			if len(one.Items) != wantItems {
				t.Errorf("limit 1 returned %d rows, want %d", len(one.Items), wantItems)
			}
			if one.Total != int64(len(tc.want)) {
				t.Errorf("limit 1 total = %d, want %d", one.Total, len(tc.want))
			}
		})
	}
}

func TestPoliciesListIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	seedPolicyFor(t, s, "t1", "", "mine", nil)
	seedPolicyFor(t, s, "t2", "", "theirs", nil)
	seedPolicyFor(t, s, "t2", "eng", "theirs-eng", nil)
	h := policiesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PoliciesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.list: %v", err)
	}
	if names := policyNames(got.Items); !reflect.DeepEqual(names, []string{"mine"}) {
		t.Errorf("t1 sees %v, want exactly [mine]", names)
	}
	if got.Total != 1 {
		t.Errorf("total = %d, want 1: the count crossed tenants", got.Total)
	}

	other, err := h(context.Background(), PoliciesListInput{}, principalFor("t2"))
	if err != nil {
		t.Fatalf("policies.list as t2: %v", err)
	}
	if names := sorted(policyNames(other.Items)); !reflect.DeepEqual(names, []string{"theirs", "theirs-eng"}) {
		t.Errorf("t2 sees %v, want its own two", names)
	}
}

func TestPoliciesListEmptyItemsMarshalAsAnArray(t *testing.T) {
	h := policiesListHandler(Deps{Engine: engineOver(t, memory.New())})
	got, err := h(context.Background(), PoliciesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.list: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"items":[]`) {
		t.Errorf("empty list marshals as %s, want items as []", raw)
	}
}

// policyFlags is what a list row must say about a policy.
type policyFlags struct {
	state                                   string
	failsClosed, neverApplies, matchesEvery bool
}

// TestPoliciesListRowsAgreeWithTheAnalysis seeds one policy of each kind and
// checks each row against analysePolicy (so the projection cannot drift from
// the analysis) and against the literal answer (so a wrong analysis cannot
// hide behind a matching projection).
func TestPoliciesListRowsAgreeWithTheAnalysis(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-48*time.Hour), now.Add(48*time.Hour)
	brokenOp := []policy.Condition{{ID: id.NewConditionID(), Field: "subject.id", Operator: "bogus", Value: "x"}}

	for _, tc := range []struct {
		name  string
		tweak func(*policy.Policy)
		want  policyFlags
	}{
		{"active", nil, policyFlags{StateActive, false, false, true}},
		{"active and restricted", func(p *policy.Policy) {
			p.Subjects = []policy.SubjectMatch{{Kind: "user", ID: "u1"}}
			p.Actions = []string{"read"}
			p.Resources = []string{"document"}
		}, policyFlags{StateActive, false, false, false}},
		{"inactive", func(p *policy.Policy) { p.IsActive = false }, policyFlags{StateInactive, false, false, true}},
		{"scheduled", func(p *policy.Policy) { p.NotBefore = &future }, policyFlags{StateScheduled, false, false, true}},
		{"expired", func(p *policy.Policy) { p.NotAfter = &past }, policyFlags{StateExpired, false, false, true}},
		{"never", func(p *policy.Policy) { p.NotBefore = &future; p.NotAfter = &past }, policyFlags{StateNever, false, false, true}},
		{"fail-closed deny", func(p *policy.Policy) { p.Effect = policy.EffectDeny; p.Conditions = brokenOp }, policyFlags{StateActive, true, false, true}},
		{"never-applies allow", func(p *policy.Policy) { p.Conditions = brokenOp }, policyFlags{StateActive, false, true, true}},
		{"matches everything through *:*", func(p *policy.Policy) { p.Actions = []string{"*:*"} }, policyFlags{StateActive, false, false, true}},
		{"*:* on actions alone with a restricted resource", func(p *policy.Policy) {
			p.Actions = []string{"*:*"}
			p.Resources = []string{"document"}
		}, policyFlags{StateActive, false, false, false}},
		{"*.* on both actions and resources", func(p *policy.Policy) {
			p.Subjects = []policy.SubjectMatch{{}}
			p.Actions = []string{"*.*"}
			p.Resources = []string{"*"}
		}, policyFlags{StateActive, false, false, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			seeded := seedPolicy(t, s, "", "subject-under-test", tc.tweak)
			// A neighbour of a different kind, so a row cannot pass by
			// being the only one.
			seedPolicy(t, s, "", "neighbour", func(p *policy.Policy) {
				p.Effect = policy.EffectDeny
				p.Subjects = []policy.SubjectMatch{{Kind: "user", ID: "z"}}
				p.Actions = []string{"read"}
				p.Resources = []string{"document"}
			})
			h := policiesListHandler(Deps{Engine: engineOver(t, s)})
			got, err := h(context.Background(), PoliciesListInput{Search: "subject-under"}, principalFor("t1"))
			if err != nil {
				t.Fatalf("policies.list: %v", err)
			}
			if len(got.Items) != 1 {
				t.Fatalf("got %d rows, want 1", len(got.Items))
			}
			row := got.Items[0]

			a := analysePolicy(seeded, time.Now())
			if row.State != a.State || row.FailsClosed != a.FailsClosed ||
				row.NeverApplies != a.NeverApplies || row.MatchesEverything != a.MatchesEverything {
				t.Errorf("row %+v disagrees with analysePolicy %+v", row, a)
			}
			if row.State != tc.want.state {
				t.Errorf("state = %q, want %q", row.State, tc.want.state)
			}
			if row.FailsClosed != tc.want.failsClosed {
				t.Errorf("failsClosed = %v, want %v", row.FailsClosed, tc.want.failsClosed)
			}
			if row.NeverApplies != tc.want.neverApplies {
				t.Errorf("neverApplies = %v, want %v", row.NeverApplies, tc.want.neverApplies)
			}
			if row.MatchesEverything != tc.want.matchesEvery {
				t.Errorf("matchesEverything = %v, want %v", row.MatchesEverything, tc.want.matchesEvery)
			}
		})
	}
}

func TestPoliciesListRowCarriesTheStoredFields(t *testing.T) {
	s := memory.New()
	updated := time.Date(2026, 6, 1, 10, 0, 0, 0, time.FixedZone("plus5", 5*3600))
	seeded := seedPolicy(t, s, "eng", "the-policy", func(p *policy.Policy) {
		p.Description = "why it exists"
		p.Effect = policy.EffectDeny
		p.Priority = 7
		p.Version = 3
		p.UpdatedAt = updated
	})
	h := policiesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PoliciesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.list: %v", err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("got %d rows, want 1", len(got.Items))
	}
	want := PolicySummary{
		ID: seeded.ID.String(), NamespacePath: "eng", Name: "the-policy", Description: "why it exists",
		Effect: "deny", Priority: 7, IsActive: true, State: StateActive, MatchesEverything: true,
		Version: 3, UpdatedAt: "2026-06-01T05:00:00Z",
	}
	if got.Items[0] != want {
		t.Errorf("row = %+v\nwant  %+v", got.Items[0], want)
	}
}

func TestPoliciesDetailCarriesEveryField(t *testing.T) {
	s := memory.New()
	east := time.FixedZone("plus5", 5*3600)
	notBefore := time.Date(2026, 6, 1, 10, 0, 0, 0, east)
	notAfter := time.Date(2099, 7, 1, 10, 0, 0, 0, east)
	created := time.Date(2026, 5, 1, 8, 30, 0, 0, east)
	c0, c1, c2 := id.NewConditionID(), id.NewConditionID(), id.NewConditionID()
	seeded := seedPolicy(t, s, "eng", "full", func(p *policy.Policy) {
		p.Description = "everything set"
		p.Effect = policy.EffectDeny
		p.Priority = 4
		p.Version = 2
		p.NotBefore = &notBefore
		p.NotAfter = &notAfter
		p.Subjects = []policy.SubjectMatch{{Kind: "user", ID: "alice"}, {Role: "admin"}}
		p.Actions = []string{"read", "write"}
		p.Resources = []string{"document"}
		p.Obligations = []string{"audit-log", "require-mfa"}
		p.CreatedBy = "creator"
		p.UpdatedBy = "editor"
		p.CreatedAt = created
		p.Conditions = []policy.Condition{
			{ID: c0, Field: "subject.id", Operator: policy.OpEquals, Value: "alice"},
			{ID: c1, Field: "context.level", Operator: policy.OpGreaterThan, Value: "high"},
			{ID: c2, Field: "subject.id", Operator: "bogus", Value: "x"},
		}
	})
	h := policiesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PolicyDetailInput{ID: seeded.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.detail: %v", err)
	}

	if got.ID != seeded.ID.String() || got.NamespacePath != "eng" || got.Name != "full" ||
		got.Description != "everything set" || got.Effect != "deny" || got.Priority != 4 ||
		got.Version != 2 || !got.IsActive {
		t.Errorf("summary fields wrong: %+v", got.PolicySummary)
	}
	if got.State != StateActive {
		t.Errorf("state = %q, want active", got.State)
	}
	if got.NotBefore != "2026-06-01T05:00:00Z" || got.NotAfter != "2099-07-01T05:00:00Z" {
		t.Errorf("window = %q..%q, want UTC RFC3339", got.NotBefore, got.NotAfter)
	}
	if got.CreatedAt != "2026-05-01T03:30:00Z" {
		t.Errorf("createdAt = %q, want 2026-05-01T03:30:00Z", got.CreatedAt)
	}
	if got.CreatedBy != "creator" || got.UpdatedBy != "editor" {
		t.Errorf("createdBy/updatedBy = %q/%q", got.CreatedBy, got.UpdatedBy)
	}
	if want := []PolicySubject{{Kind: "user", ID: "alice"}, {Role: "admin"}}; !reflect.DeepEqual(got.Subjects, want) {
		t.Errorf("subjects = %+v, want %+v", got.Subjects, want)
	}
	if !reflect.DeepEqual(got.Actions, []string{"read", "write"}) || !reflect.DeepEqual(got.Resources, []string{"document"}) {
		t.Errorf("actions/resources = %v / %v", got.Actions, got.Resources)
	}
	if !reflect.DeepEqual(got.Obligations, []string{"audit-log", "require-mfa"}) {
		t.Errorf("obligations = %v", got.Obligations)
	}
	if got.SubjectsUnrestricted || got.ActionsUnrestricted || got.ResourcesUnrestricted {
		t.Errorf("unrestricted flags = %v/%v/%v, want all false", got.SubjectsUnrestricted, got.ActionsUnrestricted, got.ResourcesUnrestricted)
	}
	if !got.HasRoleMatcher {
		t.Error("hasRoleMatcher = false, want true for a subject with a role")
	}

	if len(got.Conditions) != 3 {
		t.Fatalf("got %d conditions, want 3", len(got.Conditions))
	}
	for i, want := range []struct {
		id, field, operator, problem, reason string
	}{
		{c0.String(), "subject.id", "eq", "", ""},
		{c1.String(), "context.level", "gt", string(ProblemAlwaysFalse), string(ReasonNotANumber)},
		{c2.String(), "subject.id", "bogus", string(ProblemThrows), string(ReasonUnknownOperator)},
	} {
		c := got.Conditions[i]
		if c.ID != want.id || c.Field != want.field || c.Operator != want.operator {
			t.Errorf("condition %d = %s %s %s, want %s %s %s", i, c.ID, c.Field, c.Operator, want.id, want.field, want.operator)
		}
		if c.Problem != want.problem || c.Reason != want.reason {
			t.Errorf("condition %d problem/reason = %q/%q, want %q/%q", i, c.Problem, c.Reason, want.problem, want.reason)
		}
	}
	if c := got.Conditions[1]; c.Value != "high" {
		t.Errorf("condition 1 value = %v, want high", c.Value)
	}

	// The first condition with a fixed outcome decides, and that is the
	// alwaysFalse at index 1, not the throwing one after it.
	if got.DecidingCondition == nil || *got.DecidingCondition != 1 {
		t.Fatalf("decidingCondition = %v, want 1", got.DecidingCondition)
	}
	if !got.NeverApplies || got.FailsClosed {
		t.Errorf("neverApplies/failsClosed = %v/%v, want true/false", got.NeverApplies, got.FailsClosed)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"decidingCondition":1`) {
		t.Errorf("JSON lacks decidingCondition:1: %s", raw)
	}
	// The clean condition carries neither key.
	var wire struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := wire.Conditions[0]["problem"]; ok {
		t.Errorf("a clean condition carries a problem key: %v", wire.Conditions[0])
	}
	if wire.Conditions[1]["problem"] != "alwaysFalse" || wire.Conditions[1]["reason"] != "notANumber" {
		t.Errorf("condition 1 wire = %v", wire.Conditions[1])
	}
}

func TestPoliciesDetailDecidingConditionIsAbsentUnlessSetAndPresentAtIndexZero(t *testing.T) {
	s := memory.New()
	clean := seedPolicy(t, s, "", "clean", func(p *policy.Policy) {
		p.Conditions = []policy.Condition{{ID: id.NewConditionID(), Field: "subject.id", Operator: policy.OpEquals, Value: "a"}}
	})
	first := seedPolicy(t, s, "", "first", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Conditions = []policy.Condition{{ID: id.NewConditionID(), Field: "subject.id", Operator: "bogus", Value: "a"}}
	})
	h := policiesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PolicyDetailInput{ID: clean.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.detail (clean): %v", err)
	}
	if got.DecidingCondition != nil {
		t.Errorf("clean policy decidingCondition = %d, want nil", *got.DecidingCondition)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "decidingCondition") {
		t.Errorf("a policy with nothing deciding carries decidingCondition: %s", raw)
	}

	got, err = h(context.Background(), PolicyDetailInput{ID: first.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.detail (first): %v", err)
	}
	raw, _ = json.Marshal(got)
	if !strings.Contains(string(raw), `"decidingCondition":0`) {
		t.Errorf("index 0 must serialise as 0, not vanish: %s", raw)
	}
	if !got.FailsClosed {
		t.Error("a deny with a throwing condition should fail closed")
	}
}

func TestPoliciesDetailEmptyListsMarshalAsArraysNotNull(t *testing.T) {
	s := memory.New()
	// A store may hand back nil slices for a policy written without them.
	seeded := seedPolicy(t, s, "", "bare", nil)
	h := policiesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PolicyDetailInput{ID: seeded.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.detail: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"subjects":[]`, `"actions":[]`, `"resources":[]`, `"conditions":[]`, `"obligations":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON lacks %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "null") {
		t.Errorf("JSON carries a null: %s", raw)
	}
	for _, absent := range []string{"notBefore", "notAfter", "decidingCondition", "createdBy", "updatedBy"} {
		if strings.Contains(string(raw), `"`+absent+`"`) {
			t.Errorf("JSON carries %s for a policy that has none: %s", absent, raw)
		}
	}
	if !got.SubjectsUnrestricted || !got.ActionsUnrestricted || !got.ResourcesUnrestricted {
		t.Errorf("a policy naming nothing is unrestricted on all three: %v/%v/%v",
			got.SubjectsUnrestricted, got.ActionsUnrestricted, got.ResourcesUnrestricted)
	}
}

func TestPoliciesDetailOfAnotherTenantsPolicyIsNotFound(t *testing.T) {
	s := memory.New()
	theirs := seedPolicyFor(t, s, "t2", "", "theirs", nil)
	h := policiesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), PolicyDetailInput{ID: theirs.ID.String()}, principalFor("t1"))
	if err == nil {
		t.Fatalf("t1 read t2's policy: %+v", got)
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Errorf("want CodeNotFound, got %v", err)
	}
	if got.Name != "" {
		t.Errorf("a refused read still returned data: %+v", got)
	}
}

func TestPoliciesDetailOfAnUnknownPolicyIsNotFound(t *testing.T) {
	h := policiesDetailHandler(Deps{Engine: engineOver(t, memory.New())})
	_, err := h(context.Background(), PolicyDetailInput{ID: id.NewPolicyID().String()}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Errorf("want CodeNotFound, got %v", err)
	}
}

func TestPoliciesDetailRejectsAMalformedID(t *testing.T) {
	h := policiesDetailHandler(Deps{Engine: engineOver(t, memory.New())})
	for _, raw := range []string{"", "nope", id.NewRoleID().String()} {
		_, err := h(context.Background(), PolicyDetailInput{ID: raw}, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("id %q: want CodeBadRequest, got %v", raw, err)
			continue
		}
		if !strings.Contains(ce.Message, "not a policy id") {
			t.Errorf("id %q: message = %q", raw, ce.Message)
		}
	}
}

// TestPoliciesDetailReportsEachUnrestrictedFlagIndependently seeds policies
// where exactly one of the three matcher lists is open, so a projection that
// copies one flag into another (or reports the combined matchesEverything in
// place of them) is caught in the JSON a page reads.
func TestPoliciesDetailReportsEachUnrestrictedFlagIndependently(t *testing.T) {
	restrictedSubjects := []policy.SubjectMatch{{Kind: "user", ID: "alice"}}
	for _, tc := range []struct {
		name                         string
		tweak                        func(*policy.Policy)
		subjects, actions, resources bool
	}{
		{"open actions only", func(p *policy.Policy) {
			p.Subjects = restrictedSubjects
			p.Actions = []string{"*:*"}
			p.Resources = []string{"document:readme"}
		}, false, true, false},
		{"open resources only", func(p *policy.Policy) {
			p.Subjects = restrictedSubjects
			p.Actions = []string{"read"}
			p.Resources = []string{"*:*"}
		}, false, false, true},
		{"open subjects only, through an empty matcher", func(p *policy.Policy) {
			p.Subjects = []policy.SubjectMatch{{}}
			p.Actions = []string{"read"}
			p.Resources = []string{"document:readme"}
		}, true, false, false},
		{"open subjects only, through no matchers", func(p *policy.Policy) {
			p.Actions = []string{"read"}
			p.Resources = []string{"document:readme"}
		}, true, false, false},
		{"open actions through a bare star, resources through a dotted one", func(p *policy.Policy) {
			p.Subjects = restrictedSubjects
			p.Actions = []string{"*"}
			p.Resources = []string{"*.*"}
		}, false, true, true},
		{"a wildcard among restricted entries still opens the list", func(p *policy.Policy) {
			p.Subjects = restrictedSubjects
			p.Actions = []string{"read", "*:*"}
			p.Resources = []string{"document:readme"}
		}, false, true, false},
		{"a partial wildcard restricts", func(p *policy.Policy) {
			p.Subjects = restrictedSubjects
			p.Actions = []string{"read:*"}
			p.Resources = []string{"document:*"}
		}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			seeded := seedPolicy(t, s, "", "flags", tc.tweak)
			h := policiesDetailHandler(Deps{Engine: engineOver(t, s)})
			got, err := h(context.Background(), PolicyDetailInput{ID: seeded.ID.String()}, principalFor("t1"))
			if err != nil {
				t.Fatalf("policies.detail: %v", err)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var wire map[string]any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for key, want := range map[string]bool{
				"subjectsUnrestricted":  tc.subjects,
				"actionsUnrestricted":   tc.actions,
				"resourcesUnrestricted": tc.resources,
				"matchesEverything":     tc.subjects && tc.actions && tc.resources,
			} {
				if wire[key] != want {
					t.Errorf("%s = %v, want %v (JSON %s)", key, wire[key], want, raw)
				}
			}
		})
	}
}

// TestPoliciesDetailCarriesTheNewestReasonsOnTheWire checks the two reasons
// added after the first cut, alwaysPresent and matchesAnything, at their own
// condition index in the JSON. The expected values are also compared with
// classifyCondition, so the test follows the analysis rather than restating
// it.
func TestPoliciesDetailCarriesTheNewestReasonsOnTheWire(t *testing.T) {
	conds := []policy.Condition{
		{ID: id.NewConditionID(), Field: "context.ip", Operator: policy.OpStartsWith, Value: ""},
		{ID: id.NewConditionID(), Field: "subject.id", Operator: policy.OpExists},
		{ID: id.NewConditionID(), Field: "subject.id", Operator: policy.OpNotExists},
		{ID: id.NewConditionID(), Field: "subject.id", Operator: policy.OpEquals, Value: "alice"},
	}
	s := memory.New()
	seeded := seedPolicy(t, s, "", "reasons", func(p *policy.Policy) { p.Conditions = conds })
	h := policiesDetailHandler(Deps{Engine: engineOver(t, s)})
	got, err := h(context.Background(), PolicyDetailInput{ID: seeded.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.detail: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire struct {
		Conditions        []map[string]any `json:"conditions"`
		DecidingCondition *int             `json:"decidingCondition"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(wire.Conditions) != len(conds) {
		t.Fatalf("got %d conditions on the wire, want %d", len(wire.Conditions), len(conds))
	}

	for i, want := range []struct{ problem, reason string }{
		{"alwaysTrue", "matchesAnything"},
		{"alwaysTrue", "alwaysPresent"},
		{"alwaysFalse", "alwaysPresent"},
		{"", ""},
	} {
		// The committed classification is the authority for the expectation.
		p, r := classifyCondition(conds[i])
		if string(p) != want.problem || string(r) != want.reason {
			t.Fatalf("condition %d: classifyCondition = %q/%q, this test expects %q/%q", i, p, r, want.problem, want.reason)
		}
		gotProblem, hasProblem := wire.Conditions[i]["problem"]
		gotReason, hasReason := wire.Conditions[i]["reason"]
		if want.problem == "" {
			if hasProblem || hasReason {
				t.Errorf("condition %d is clean but carries %v/%v", i, gotProblem, gotReason)
			}
			continue
		}
		if gotProblem != want.problem || gotReason != want.reason {
			t.Errorf("condition %d wire problem/reason = %v/%v, want %s/%s", i, gotProblem, gotReason, want.problem, want.reason)
		}
	}
	// alwaysTrue conditions restrict nothing but decide nothing; the first
	// alwaysFalse one is the deciding condition.
	if wire.DecidingCondition == nil || *wire.DecidingCondition != 2 {
		t.Errorf("decidingCondition = %v, want 2", wire.DecidingCondition)
	}
}
