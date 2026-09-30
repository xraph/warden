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

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
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

// ---------------------------------------------------------------------------
// Writes: policies.create, policies.update, policies.setActive, policies.delete
// ---------------------------------------------------------------------------

// policyProbe adds the three policy hooks to auditProbe.
type policyProbe struct{ *auditProbe }

func (p policyProbe) OnPolicyCreated(context.Context, *policy.Policy) error {
	p.note("policy.created")
	return nil
}

func (p policyProbe) OnPolicyUpdated(context.Context, *policy.Policy) error {
	p.note("policy.updated")
	return nil
}

func (p policyProbe) OnPolicyDeleted(context.Context, id.PolicyID) error {
	p.note("policy.deleted")
	return nil
}

func (a *auditProbe) emitted() (events, typed int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events), len(a.typed)
}

func policyProbedEngine(t *testing.T, s *memory.Store) (*warden.Engine, policyProbe) {
	t.Helper()
	probe := policyProbe{&auditProbe{}}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng, probe
}

func wantCode(t *testing.T, err error, code dashcontract.ErrorCode) *dashcontract.Error {
	t.Helper()
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != code {
		t.Fatalf("want error code %v, got %v", code, err)
	}
	return ce
}

func storedPolicy(t *testing.T, s *memory.Store, pid string) *policy.Policy {
	t.Helper()
	parsed, err := id.ParsePolicyID(pid)
	if err != nil {
		t.Fatalf("parse policy id %q: %v", pid, err)
	}
	got, err := s.GetPolicy(context.Background(), "t1", parsed)
	if err != nil {
		t.Fatalf("stored policy %s: %v", pid, err)
	}
	return got
}

func policyCount(t *testing.T, s *memory.Store, tenant string) int {
	t.Helper()
	rows, err := s.ListPolicies(context.Background(), &policy.ListFilter{TenantID: tenant})
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	return len(rows)
}

// diffPolicy names the fields two stored policies disagree on, ignoring the
// three an update stamps (Version, UpdatedAt, UpdatedBy), which have their
// own assertions.
func diffPolicy(a, b *policy.Policy) []string {
	var out []string
	av, bv := reflect.ValueOf(*a), reflect.ValueOf(*b)
	for i := 0; i < av.NumField(); i++ {
		name := av.Type().Field(i).Name
		switch name {
		case "Version", "UpdatedAt", "UpdatedBy":
			continue
		}
		if !reflect.DeepEqual(av.Field(i).Interface(), bv.Field(i).Interface()) {
			out = append(out, name)
		}
	}
	return out
}

// fullPolicy seeds a policy with every field set, active, so an update test
// can tell exactly which field moved.
func fullPolicy(t *testing.T, s *memory.Store, namespace, name string) *policy.Policy {
	t.Helper()
	nb := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	na := time.Date(2026, 12, 31, 17, 0, 0, 0, time.UTC)
	return seedPolicy(t, s, namespace, name, func(p *policy.Policy) {
		p.Description = "the original description"
		p.Effect = policy.EffectDeny
		p.Priority = 7
		p.IsActive = true
		p.NotBefore = &nb
		p.NotAfter = &na
		p.Subjects = []policy.SubjectMatch{{Kind: "user", Role: "admin"}}
		p.Actions = []string{"read", "write"}
		p.Resources = []string{"document:*"}
		p.Obligations = []string{"audit-log"}
		p.Metadata = map[string]any{"owner": "platform"}
		p.CreatedBy = "seeder"
		p.UpdatedBy = "seeder"
		p.Conditions = []policy.Condition{
			{ID: id.NewConditionID(), Field: "subject.level", Operator: policy.OpGTE, Value: float64(3)},
			{ID: id.NewConditionID(), Field: "context.ip", Operator: policy.OpIPInCIDR, Value: []any{"10.0.0.0/8"}},
		}
	})
}

func TestPoliciesCreateStoresInactiveWithEveryFieldTrimmedAndFresh(t *testing.T) {
	s := memory.New()
	h := policiesCreateHandler(Deps{Engine: engineOver(t, s)})

	// The wire input carries isActive: true. There is no such input field,
	// so it must be ignored and the policy stored inactive.
	var in PolicyCreateInput
	raw := `{"name":"  office hours  ","description":"d","effect":"deny","priority":4,
		"notBefore":"2026-01-01T09:00:00Z","notAfter":"2026-06-01T17:00:00+02:00",
		"subjects":[{"kind":" user ","id":" u1 ","role":" admin "}],
		"actions":[" read "," write"],"resources":["document:* "],
		"conditions":[{"id":"not-an-id","field":"  subject.level ","operator":"gte","value":3},
		              {"field":"context.ip","operator":"ip_in_cidr","value":["10.0.0.0/8"]}],
		"obligations":[" audit-log "],"namespacePath":"eng","isActive":true}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	ack, err := h(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.create: %v", err)
	}
	if ack.ID == "" {
		t.Fatal("create returned no id for the page to navigate to")
	}
	got := storedPolicy(t, s, ack.ID)

	if got.IsActive {
		t.Error("a created policy must be stored inactive")
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if got.TenantID != "t1" || got.NamespacePath != "eng" {
		t.Errorf("tenant/namespace = %q/%q, want t1/eng", got.TenantID, got.NamespacePath)
	}
	if got.Name != "office hours" {
		t.Errorf("name = %q, want it trimmed", got.Name)
	}
	if got.Description != "d" || got.Effect != policy.EffectDeny || got.Priority != 4 {
		t.Errorf("description/effect/priority = %q/%q/%d", got.Description, got.Effect, got.Priority)
	}
	if got.NotBefore == nil || !got.NotBefore.Equal(time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("notBefore = %v", got.NotBefore)
	}
	if got.NotAfter == nil || !got.NotAfter.Equal(time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)) {
		t.Errorf("notAfter = %v, want 2026-06-01T15:00:00Z", got.NotAfter)
	}
	if want := []policy.SubjectMatch{{Kind: "user", ID: "u1", Role: "admin"}}; !reflect.DeepEqual(got.Subjects, want) {
		t.Errorf("subjects = %+v, want %+v", got.Subjects, want)
	}
	if want := []string{"read", "write"}; !reflect.DeepEqual(got.Actions, want) {
		t.Errorf("actions = %q, want %q", got.Actions, want)
	}
	if want := []string{"document:*"}; !reflect.DeepEqual(got.Resources, want) {
		t.Errorf("resources = %q, want %q", got.Resources, want)
	}
	if want := []string{"audit-log"}; !reflect.DeepEqual(got.Obligations, want) {
		t.Errorf("obligations = %q, want %q", got.Obligations, want)
	}
	if len(got.Conditions) != 2 {
		t.Fatalf("stored %d conditions, want 2", len(got.Conditions))
	}
	c0, c1 := got.Conditions[0], got.Conditions[1]
	if c0.Field != "subject.level" || c0.Operator != policy.OpGTE || c0.Value != float64(3) {
		t.Errorf("condition 0 = %+v, want the trimmed field stored", c0)
	}
	if c1.Field != "context.ip" || c1.Operator != policy.OpIPInCIDR || !reflect.DeepEqual(c1.Value, []any{"10.0.0.0/8"}) {
		t.Errorf("condition 1 = %+v", c1)
	}
	if c0.ID.IsNil() || c1.ID.IsNil() || c0.ID == c1.ID {
		t.Errorf("conditions must each get a fresh id, got %s and %s", c0.ID, c1.ID)
	}
	if got.CreatedBy != "tester" || got.UpdatedBy != "tester" {
		t.Errorf("createdBy/updatedBy = %q/%q, want tester", got.CreatedBy, got.UpdatedBy)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("timestamps were not set")
	}
}

func TestPoliciesCreateWithNoMatchersStoresEmptyListsAndStaysInactive(t *testing.T) {
	// The reason a create is never active: with no matchers this policy
	// matches every check in its namespace and below.
	s := memory.New()
	ack, err := policiesCreateHandler(Deps{Engine: engineOver(t, s)})(context.Background(),
		PolicyCreateInput{PolicyDraft: PolicyDraft{Name: "everything", Effect: "allow"}}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.create: %v", err)
	}
	got := storedPolicy(t, s, ack.ID)
	if got.IsActive {
		t.Fatal("an allow with no matchers was stored active: it would grant everything")
	}
	if got.Subjects == nil || got.Actions == nil || got.Resources == nil || got.Conditions == nil {
		t.Errorf("empty lists must be stored as empty lists, not nil: %+v", got)
	}
	if got.NotBefore != nil || got.NotAfter != nil {
		t.Errorf("no window was given, got %v %v", got.NotBefore, got.NotAfter)
	}
}

func TestPolicyCreateInputHasNoIsActive(t *testing.T) {
	typ := reflect.TypeOf(PolicyCreateInput{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(strings.ToLower(typ.Field(i).Name), "active") {
			t.Fatalf("PolicyCreateInput has field %s: a create must not choose to be active", typ.Field(i).Name)
		}
	}
	draft := reflect.TypeOf(PolicyDraft{})
	for i := 0; i < draft.NumField(); i++ {
		if strings.Contains(strings.ToLower(draft.Field(i).Name), "active") {
			t.Fatalf("PolicyDraft has field %s", draft.Field(i).Name)
		}
	}
}

func TestPoliciesCreateRefusesEachDraftIssueAndStoresNothing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PolicyDraft)
		field  string
	}{
		{"no name", func(d *PolicyDraft) { d.Name = "  " }, "name"},
		{"a bad effect", func(d *PolicyDraft) { d.Effect = "permit" }, "effect"},
		{"a window that ends before it starts", func(d *PolicyDraft) {
			d.NotBefore, d.NotAfter = "2026-06-01T00:00:00Z", "2026-01-01T00:00:00Z"
		}, "window"},
		{"an empty subject", func(d *PolicyDraft) { d.Subjects = []PolicySubject{{}} }, "subjects"},
		{"a subject that is only whitespace", func(d *PolicyDraft) { d.Subjects = []PolicySubject{{ID: "  "}} }, "subjects"},
		{"a blank action", func(d *PolicyDraft) { d.Actions = []string{"read", " "} }, "actions"},
		{"a blank resource", func(d *PolicyDraft) { d.Resources = []string{""} }, "resources"},
		{"a blank obligation", func(d *PolicyDraft) { d.Obligations = []string{" "} }, "obligations"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			eng, probe := policyProbedEngine(t, s)
			d := cleanDraft()
			tc.mutate(&d)
			_, err := policiesCreateHandler(Deps{Engine: eng})(context.Background(), PolicyCreateInput{PolicyDraft: d}, principalFor("t1"))
			ce := wantCode(t, err, dashcontract.CodeBadRequest)
			fields, ok := ce.Details["fields"].(map[string]string)
			if !ok || fields[tc.field] == "" {
				t.Errorf("details.fields = %#v, want an entry for %q", ce.Details["fields"], tc.field)
			}
			if _, ok := ce.Details["conditions"]; !ok {
				t.Error("details carries no conditions key")
			}
			if n := policyCount(t, s, "t1"); n != 0 {
				t.Errorf("a refused create stored %d policies", n)
			}
			if ev, ty := probe.emitted(); ev != 0 || ty != 0 {
				t.Errorf("a refused create emitted %d audit events and %d hooks", ev, ty)
			}
		})
	}
}

func TestPoliciesCreateNamesTheBadConditionByIndex(t *testing.T) {
	s := memory.New()
	eng, probe := policyProbedEngine(t, s)
	d := cleanDraft()
	d.Conditions = []PolicyCondition{
		goodCondition(),
		goodCondition(),
		{Field: "subject.id", Operator: "regex", Value: "(unclosed"},
	}
	_, err := policiesCreateHandler(Deps{Engine: eng})(context.Background(), PolicyCreateInput{PolicyDraft: d}, principalFor("t1"))
	ce := wantCode(t, err, dashcontract.CodeBadRequest)
	conds, ok := ce.Details["conditions"].([]ConditionIssue)
	if !ok || len(conds) != 1 {
		t.Fatalf("details.conditions = %#v, want exactly one entry", ce.Details["conditions"])
	}
	if conds[0].Index != 2 || conds[0].Message == "" {
		t.Errorf("condition issue = %+v, want index 2 with a message", conds[0])
	}
	if n := policyCount(t, s, "t1"); n != 0 {
		t.Errorf("a refused create stored %d policies", n)
	}
	if ev, ty := probe.emitted(); ev != 0 || ty != 0 {
		t.Errorf("a refused create emitted %d audit events and %d hooks", ev, ty)
	}
}

func TestPoliciesCreateRefusesADuplicateNameInTheSameNamespaceOnly(t *testing.T) {
	s := memory.New()
	eng, probe := policyProbedEngine(t, s)
	h := policiesCreateHandler(Deps{Engine: eng})
	ctx := context.Background()
	mk := func(ns string) error {
		_, err := h(ctx, PolicyCreateInput{PolicyDraft: cleanDraft(), NamespacePath: ns}, principalFor("t1"))
		return err
	}
	if err := mk("eng"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	evBefore, tyBefore := probe.emitted()
	wantCode(t, mk("eng"), dashcontract.CodeConflict)
	if ev, ty := probe.emitted(); ev != evBefore || ty != tyBefore {
		t.Errorf("a refused duplicate emitted %d audit events and %d hooks", ev-evBefore, ty-tyBefore)
	}
	if err := mk("ops"); err != nil {
		t.Errorf("the same name in another namespace must succeed: %v", err)
	}
	if n := policyCount(t, s, "t1"); n != 2 {
		t.Errorf("stored %d policies, want 2", n)
	}
}

func TestPoliciesCreateRefusesAnInvalidNamespace(t *testing.T) {
	s := memory.New()
	h := policiesCreateHandler(Deps{Engine: engineOver(t, s)})
	for _, ns := range []string{"/eng", "eng/", "eng//platform", "Eng Platform"} {
		_, err := h(context.Background(), PolicyCreateInput{PolicyDraft: cleanDraft(), NamespacePath: ns}, principalFor("t1"))
		wantCode(t, err, dashcontract.CodeBadRequest)
	}
	if n := policyCount(t, s, "t1"); n != 0 {
		t.Errorf("a refused create stored %d policies", n)
	}
}

func TestPoliciesUpdatePatchesOnlyThePresentField(t *testing.T) {
	newWindow := "2026-03-01T00:00:00Z"
	cases := []struct {
		name  string
		patch func(*PolicyUpdateInput)
		moved string
	}{
		{"name", func(in *PolicyUpdateInput) { in.Name = strPtr("renamed") }, "Name"},
		{"description", func(in *PolicyUpdateInput) { in.Description = strPtr("new words") }, "Description"},
		{"effect", func(in *PolicyUpdateInput) { in.Effect = strPtr("allow") }, "Effect"},
		{"priority", func(in *PolicyUpdateInput) { n := 99; in.Priority = &n }, "Priority"},
		{"notBefore", func(in *PolicyUpdateInput) { in.NotBefore = &newWindow }, "NotBefore"},
		{"notAfter", func(in *PolicyUpdateInput) { v := "2027-01-01T00:00:00Z"; in.NotAfter = &v }, "NotAfter"},
		{"subjects", func(in *PolicyUpdateInput) { v := []PolicySubject{{Kind: "service"}}; in.Subjects = &v }, "Subjects"},
		{"actions", func(in *PolicyUpdateInput) { v := []string{"delete"}; in.Actions = &v }, "Actions"},
		{"resources", func(in *PolicyUpdateInput) { v := []string{"invoice:*"}; in.Resources = &v }, "Resources"},
		{"conditions", func(in *PolicyUpdateInput) { v := []PolicyCondition{goodCondition()}; in.Conditions = &v }, "Conditions"},
		{"obligations", func(in *PolicyUpdateInput) { v := []string{"notify"}; in.Obligations = &v }, "Obligations"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			orig := fullPolicy(t, s, "eng", "target")
			before := storedPolicy(t, s, orig.ID.String())
			in := PolicyUpdateInput{ID: orig.ID.String()}
			tc.patch(&in)
			ack, err := policiesUpdateHandler(Deps{Engine: engineOver(t, s)})(context.Background(), in, principalFor("t1"))
			if err != nil {
				t.Fatalf("policies.update: %v", err)
			}
			if ack != (AckResponse{}) {
				t.Errorf("update returned %+v, want an empty ack", ack)
			}
			after := storedPolicy(t, s, orig.ID.String())
			if got := diffPolicy(before, after); !reflect.DeepEqual(got, []string{tc.moved}) {
				t.Errorf("update of %s moved %v, want only [%s]", tc.name, got, tc.moved)
			}
			if after.Version != before.Version+1 {
				t.Errorf("version = %d, want %d", after.Version, before.Version+1)
			}
			if after.UpdatedBy != "tester" {
				t.Errorf("updatedBy = %q, want tester", after.UpdatedBy)
			}
			if after.CreatedBy != "seeder" {
				t.Errorf("createdBy = %q, must not change", after.CreatedBy)
			}
			if !after.IsActive {
				t.Error("an update must not change whether the policy is active")
			}
		})
	}
}

func TestPoliciesUpdateStoresTheNewValues(t *testing.T) {
	s := memory.New()
	orig := fullPolicy(t, s, "eng", "target")
	keep := orig.Conditions[0].ID.String()
	in := PolicyUpdateInput{
		ID:          orig.ID.String(),
		Name:        strPtr("  padded name  "),
		Subjects:    &[]PolicySubject{{Kind: " user ", Role: " ops "}},
		Actions:     &[]string{" a ", "b "},
		Resources:   &[]string{" r"},
		Obligations: &[]string{" o "},
		Conditions: &[]PolicyCondition{
			{ID: keep, Field: " subject.level ", Operator: "gte", Value: float64(5)},
			{Field: "context.ip", Operator: "ip_in_cidr", Value: []any{"192.168.0.0/16"}},
		},
	}
	if _, err := policiesUpdateHandler(Deps{Engine: engineOver(t, s)})(context.Background(), in, principalFor("t1")); err != nil {
		t.Fatalf("policies.update: %v", err)
	}
	got := storedPolicy(t, s, orig.ID.String())
	if got.Name != "padded name" {
		t.Errorf("name = %q, want it trimmed", got.Name)
	}
	if want := []policy.SubjectMatch{{Kind: "user", Role: "ops"}}; !reflect.DeepEqual(got.Subjects, want) {
		t.Errorf("subjects = %+v, want %+v", got.Subjects, want)
	}
	if !reflect.DeepEqual(got.Actions, []string{"a", "b"}) || !reflect.DeepEqual(got.Resources, []string{"r"}) ||
		!reflect.DeepEqual(got.Obligations, []string{"o"}) {
		t.Errorf("lists = %q %q %q, want them trimmed", got.Actions, got.Resources, got.Obligations)
	}
	if len(got.Conditions) != 2 {
		t.Fatalf("stored %d conditions, want 2", len(got.Conditions))
	}
	if got.Conditions[0].ID.String() != keep || got.Conditions[0].Field != "subject.level" || got.Conditions[0].Value != float64(5) {
		t.Errorf("condition 0 = %+v, want the sent id kept, the field trimmed and the value updated", got.Conditions[0])
	}
	if got.Conditions[1].ID.IsNil() || got.Conditions[1].ID == got.Conditions[0].ID {
		t.Errorf("condition 1 has id %s, want a fresh one", got.Conditions[1].ID)
	}
	// Untouched.
	if got.Description != "the original description" || got.Priority != 7 || got.Effect != policy.EffectDeny ||
		got.NotBefore == nil || got.NotAfter == nil || got.Metadata["owner"] != "platform" {
		t.Errorf("fields the patch did not name changed: %+v", got)
	}
}

func TestPoliciesUpdateEmptyConditionsClearsAndAbsentLeavesAlone(t *testing.T) {
	s := memory.New()
	orig := fullPolicy(t, s, "", "target")
	h := policiesUpdateHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	if _, err := h(ctx, PolicyUpdateInput{ID: orig.ID.String(), Description: strPtr("x")}, principalFor("t1")); err != nil {
		t.Fatalf("update without conditions: %v", err)
	}
	if got := storedPolicy(t, s, orig.ID.String()); !reflect.DeepEqual(got.Conditions, orig.Conditions) {
		t.Errorf("absent conditions changed the stored ones: %+v", got.Conditions)
	}

	empty := []PolicyCondition{}
	if _, err := h(ctx, PolicyUpdateInput{ID: orig.ID.String(), Conditions: &empty}, principalFor("t1")); err != nil {
		t.Fatalf("update with empty conditions: %v", err)
	}
	if got := storedPolicy(t, s, orig.ID.String()); len(got.Conditions) != 0 {
		t.Errorf("conditions: [] left %d conditions", len(got.Conditions))
	}

	// The same over the wire: [] is a present, empty pointer, and absent is nil.
	var in PolicyUpdateInput
	if err := json.Unmarshal([]byte(`{"id":"x","conditions":[]}`), &in); err != nil || in.Conditions == nil {
		t.Errorf("a wire [] must decode to a present pointer, got %v (err %v)", in.Conditions, err)
	}
	in = PolicyUpdateInput{}
	if err := json.Unmarshal([]byte(`{"id":"x"}`), &in); err != nil || in.Conditions != nil {
		t.Errorf("an absent field must decode to nil, got %v (err %v)", in.Conditions, err)
	}
}

func TestPoliciesUpdateWindow(t *testing.T) {
	// The stored window is 2026-01-01T09:00Z to 2026-12-31T17:00Z.
	h := func(s *memory.Store) func(context.Context, PolicyUpdateInput, dashcontract.Principal) (AckResponse, error) {
		return policiesUpdateHandler(Deps{Engine: engineOver(t, s)})
	}
	ctx := context.Background()

	t.Run("a start after the stored end is refused", func(t *testing.T) {
		s := memory.New()
		orig := fullPolicy(t, s, "", "w")
		_, err := h(s)(ctx, PolicyUpdateInput{ID: orig.ID.String(), NotBefore: strPtr("2027-06-01T00:00:00Z")}, principalFor("t1"))
		ce := wantCode(t, err, dashcontract.CodeBadRequest)
		if fields, _ := ce.Details["fields"].(map[string]string); fields["window"] == "" {
			t.Errorf("details.fields = %#v, want a window entry", ce.Details["fields"])
		}
		if got := storedPolicy(t, s, orig.ID.String()); got.Version != orig.Version || !got.NotBefore.Equal(*orig.NotBefore) {
			t.Errorf("a refused update changed the policy: %+v", got)
		}
	})
	t.Run("an end before the stored start is refused", func(t *testing.T) {
		s := memory.New()
		orig := fullPolicy(t, s, "", "w")
		_, err := h(s)(ctx, PolicyUpdateInput{ID: orig.ID.String(), NotAfter: strPtr("2025-01-01T00:00:00Z")}, principalFor("t1"))
		wantCode(t, err, dashcontract.CodeBadRequest)
	})
	t.Run("a start that is not a time is refused", func(t *testing.T) {
		s := memory.New()
		orig := fullPolicy(t, s, "", "w")
		_, err := h(s)(ctx, PolicyUpdateInput{ID: orig.ID.String(), NotBefore: strPtr("tomorrow")}, principalFor("t1"))
		wantCode(t, err, dashcontract.CodeBadRequest)
	})
	t.Run("an empty string clears only that bound", func(t *testing.T) {
		s := memory.New()
		orig := fullPolicy(t, s, "", "w")
		if _, err := h(s)(ctx, PolicyUpdateInput{ID: orig.ID.String(), NotBefore: strPtr("")}, principalFor("t1")); err != nil {
			t.Fatalf("clear notBefore: %v", err)
		}
		got := storedPolicy(t, s, orig.ID.String())
		if got.NotBefore != nil {
			t.Errorf("notBefore = %v, want it cleared", got.NotBefore)
		}
		if got.NotAfter == nil || !got.NotAfter.Equal(*orig.NotAfter) {
			t.Errorf("notAfter = %v, want it untouched", got.NotAfter)
		}
	})
	t.Run("a start alone, before the stored end, is accepted", func(t *testing.T) {
		s := memory.New()
		orig := fullPolicy(t, s, "", "w")
		if _, err := h(s)(ctx, PolicyUpdateInput{ID: orig.ID.String(), NotBefore: strPtr("2026-02-01T00:00:00Z")}, principalFor("t1")); err != nil {
			t.Fatalf("update notBefore: %v", err)
		}
		got := storedPolicy(t, s, orig.ID.String())
		if got.NotBefore == nil || !got.NotBefore.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("notBefore = %v", got.NotBefore)
		}
	})
	t.Run("a policy with a stored window that is already bad can change its description", func(t *testing.T) {
		s := memory.New()
		orig := fullPolicy(t, s, "", "w")
		bad := orig.NotBefore.Add(-time.Hour)
		orig.NotAfter = &bad
		if err := s.UpdatePolicy(ctx, orig); err != nil {
			t.Fatal(err)
		}
		if _, err := h(s)(ctx, PolicyUpdateInput{ID: orig.ID.String(), Description: strPtr("still editable")}, principalFor("t1")); err != nil {
			t.Fatalf("update description: %v", err)
		}
	})
}

func TestPoliciesUpdateValidatesOnlyThePartsItChanges(t *testing.T) {
	s := memory.New()
	throwing := []policy.Condition{
		{ID: id.NewConditionID(), Field: "subject.id", Operator: policy.OpRegex, Value: "(unclosed"},
	}
	// Written straight through the store, as a policy stored before this
	// validation existed would have been.
	orig := seedPolicy(t, s, "", "legacy", func(p *policy.Policy) { p.Conditions = throwing })
	eng, probe := policyProbedEngine(t, s)
	h := policiesUpdateHandler(Deps{Engine: eng})
	ctx := context.Background()

	if _, err := h(ctx, PolicyUpdateInput{ID: orig.ID.String(), Description: strPtr("now documented")}, principalFor("t1")); err != nil {
		t.Fatalf("a policy with a stored bad condition could not have its description edited: %v", err)
	}
	got := storedPolicy(t, s, orig.ID.String())
	if got.Description != "now documented" {
		t.Errorf("description = %q", got.Description)
	}
	if !reflect.DeepEqual(got.Conditions, throwing) {
		t.Errorf("the description edit changed the stored conditions: %+v", got.Conditions)
	}
	if got.Version != orig.Version+1 {
		t.Errorf("version = %d, want %d", got.Version, orig.Version+1)
	}

	evBefore, tyBefore := probe.emitted()
	bad := []PolicyCondition{{Field: "subject.id", Operator: "regex", Value: "(also unclosed"}}
	_, err := h(ctx, PolicyUpdateInput{ID: orig.ID.String(), Conditions: &bad}, principalFor("t1"))
	ce := wantCode(t, err, dashcontract.CodeBadRequest)
	conds, ok := ce.Details["conditions"].([]ConditionIssue)
	if !ok || len(conds) != 1 || conds[0].Index != 0 {
		t.Errorf("details.conditions = %#v, want one entry at index 0", ce.Details["conditions"])
	}
	after := storedPolicy(t, s, orig.ID.String())
	if !reflect.DeepEqual(after.Conditions, throwing) {
		t.Errorf("a refused update changed the stored conditions: %+v", after.Conditions)
	}
	if after.Version != got.Version {
		t.Errorf("a refused update bumped the version to %d", after.Version)
	}
	if ev, ty := probe.emitted(); ev != evBefore || ty != tyBefore {
		t.Errorf("a refused update emitted %d audit events and %d hooks", ev-evBefore, ty-tyBefore)
	}

	// A bad name is still caught, in a patch that also has a fine field.
	_, err = h(ctx, PolicyUpdateInput{ID: orig.ID.String(), Name: strPtr("  "), Description: strPtr("ok")}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeBadRequest)
	if after := storedPolicy(t, s, orig.ID.String()); after.Description != "now documented" || after.Name != "legacy" {
		t.Errorf("a refused patch was partly applied: %+v", after)
	}
}

func TestPoliciesUpdateRenameOntoAnExistingNameIsAConflict(t *testing.T) {
	s := memory.New()
	seedPolicy(t, s, "eng", "taken", nil)
	other := seedPolicy(t, s, "ops", "taken", nil)
	mine := seedPolicy(t, s, "eng", "mine", nil)
	eng, probe := policyProbedEngine(t, s)
	h := policiesUpdateHandler(Deps{Engine: eng})
	ctx := context.Background()

	_, err := h(ctx, PolicyUpdateInput{ID: mine.ID.String(), Name: strPtr("taken")}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeConflict)
	if got := storedPolicy(t, s, mine.ID.String()); got.Name != "mine" || got.Version != mine.Version {
		t.Errorf("a refused rename changed the policy: %+v", got)
	}
	if ev, ty := probe.emitted(); ev != 0 || ty != 0 {
		t.Errorf("a refused rename emitted %d audit events and %d hooks", ev, ty)
	}
	// Renaming to its own name, and to a name only another namespace holds.
	if _, err := h(ctx, PolicyUpdateInput{ID: mine.ID.String(), Name: strPtr("mine")}, principalFor("t1")); err != nil {
		t.Errorf("renaming to its own name: %v", err)
	}
	if _, err := h(ctx, PolicyUpdateInput{ID: other.ID.String(), Name: strPtr("mine")}, principalFor("t1")); err != nil {
		t.Errorf("a name held only by another namespace: %v", err)
	}
}

func TestPoliciesUpdateOfAnotherTenantsOrUnknownPolicyIsNotFound(t *testing.T) {
	s := memory.New()
	theirs := seedPolicyFor(t, s, "t2", "", "theirs", nil)
	eng, probe := policyProbedEngine(t, s)
	h := policiesUpdateHandler(Deps{Engine: eng})
	ctx := context.Background()

	_, err := h(ctx, PolicyUpdateInput{ID: theirs.ID.String(), Description: strPtr("hijack")}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeNotFound)
	_, err = h(ctx, PolicyUpdateInput{ID: id.NewPolicyID().String(), Description: strPtr("x")}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeNotFound)
	_, err = h(ctx, PolicyUpdateInput{ID: "not-an-id"}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeBadRequest)

	got, gerr := s.GetPolicy(ctx, "t2", theirs.ID)
	if gerr != nil || got.Description != "" || got.Version != theirs.Version {
		t.Errorf("another tenant's policy was touched: %+v (err %v)", got, gerr)
	}
	if ev, ty := probe.emitted(); ev != 0 || ty != 0 {
		t.Errorf("refused updates emitted %d audit events and %d hooks", ev, ty)
	}
}

func TestPoliciesSetActiveChangesOnlyTheFlagAndTheVersion(t *testing.T) {
	s := memory.New()
	orig := seedPolicy(t, s, "eng", "target", func(p *policy.Policy) {
		p.Description = "d"
		p.Priority = 3
		p.Actions = []string{"read"}
		p.Conditions = []policy.Condition{{ID: id.NewConditionID(), Field: "subject.level", Operator: policy.OpGTE, Value: float64(2)}}
		p.IsActive = false
	})
	before := storedPolicy(t, s, orig.ID.String())
	h := policiesSetActiveHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	ack, err := h(ctx, PolicySetActiveInput{ID: orig.ID.String(), Active: true}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.setActive: %v", err)
	}
	if ack != (AckResponse{}) {
		t.Errorf("setActive returned %+v, want an empty ack", ack)
	}
	on := storedPolicy(t, s, orig.ID.String())
	if !on.IsActive {
		t.Error("the policy was not activated")
	}
	if got := diffPolicy(before, on); !reflect.DeepEqual(got, []string{"IsActive"}) {
		t.Errorf("setActive moved %v, want only [IsActive]", got)
	}
	if on.Version != before.Version+1 || on.UpdatedBy != "tester" {
		t.Errorf("version/updatedBy = %d/%q, want %d/tester", on.Version, on.UpdatedBy, before.Version+1)
	}

	if _, err := h(ctx, PolicySetActiveInput{ID: orig.ID.String(), Active: false}, principalFor("t1")); err != nil {
		t.Fatalf("policies.setActive off: %v", err)
	}
	off := storedPolicy(t, s, orig.ID.String())
	if off.IsActive || off.Version != before.Version+2 {
		t.Errorf("after deactivating: active=%v version=%d", off.IsActive, off.Version)
	}
	if got := diffPolicy(before, off); len(got) != 0 {
		t.Errorf("a round trip left %v changed", got)
	}
}

func TestPoliciesSetActiveOfAnotherTenantsOrMalformedIsRefused(t *testing.T) {
	s := memory.New()
	theirs := seedPolicyFor(t, s, "t2", "", "theirs", func(p *policy.Policy) { p.IsActive = false })
	eng, probe := policyProbedEngine(t, s)
	h := policiesSetActiveHandler(Deps{Engine: eng})
	ctx := context.Background()

	_, err := h(ctx, PolicySetActiveInput{ID: theirs.ID.String(), Active: true}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeNotFound)
	_, err = h(ctx, PolicySetActiveInput{ID: "nope", Active: true}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeBadRequest)
	if got, _ := s.GetPolicy(ctx, "t2", theirs.ID); got.IsActive {
		t.Error("another tenant's policy was activated")
	}
	if ev, ty := probe.emitted(); ev != 0 || ty != 0 {
		t.Errorf("refused activations emitted %d audit events and %d hooks", ev, ty)
	}
}

func TestPoliciesDeleteRemovesItAndRefusesAnotherTenants(t *testing.T) {
	s := memory.New()
	mine := seedPolicy(t, s, "", "mine", nil)
	theirs := seedPolicyFor(t, s, "t2", "", "theirs", nil)
	eng, probe := policyProbedEngine(t, s)
	h := policiesDeleteHandler(Deps{Engine: eng})
	ctx := context.Background()

	_, err := h(ctx, PolicyDeleteInput{ID: theirs.ID.String()}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeNotFound)
	if _, gerr := s.GetPolicy(ctx, "t2", theirs.ID); gerr != nil {
		t.Errorf("another tenant's policy was deleted: %v", gerr)
	}
	_, err = h(ctx, PolicyDeleteInput{ID: "nope"}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeBadRequest)
	if ev, ty := probe.emitted(); ev != 0 || ty != 0 {
		t.Errorf("refused deletes emitted %d audit events and %d hooks", ev, ty)
	}

	ack, err := h(ctx, PolicyDeleteInput{ID: mine.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("policies.delete: %v", err)
	}
	if ack != (AckResponse{}) {
		t.Errorf("delete returned %+v, want an empty ack", ack)
	}
	if _, gerr := s.GetPolicy(ctx, "t1", mine.ID); gerr == nil {
		t.Error("the policy is still stored")
	}
	_, err = h(ctx, PolicyDeleteInput{ID: mine.ID.String()}, principalFor("t1"))
	wantCode(t, err, dashcontract.CodeNotFound)
}

func TestPoliciesWritesEmitAuditAndTheTypedHooks(t *testing.T) {
	// Each write drives the cache invalidator through both the typed hook and
	// the audit event. The audit actions are REST's own vocabulary:
	// setActive is "policy.updated", there is no "policy.activated".
	s := memory.New()
	eng, probe := policyProbedEngine(t, s)
	deps := Deps{Engine: eng}
	ctx := context.Background()
	p := principalFor("t1")

	ack, err := policiesCreateHandler(deps)(ctx, PolicyCreateInput{PolicyDraft: cleanDraft()}, p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created := probe.event(t, "policy.created")
	if created.Actor != wantActor || created.TenantID != "t1" || created.EntityID != ack.ID || created.Before != nil {
		t.Errorf("create event = %+v", created)
	}
	if ent, ok := created.Entity.(*policy.Policy); !ok || ent.ID.String() != ack.ID || ent.IsActive {
		t.Errorf("create event entity = %#v, want the stored inactive policy", created.Entity)
	}
	if !probe.hasTyped("policy.created") || probe.ctxActor != wantActor {
		t.Errorf("typed create hook missing or the context carries actor %+v", probe.ctxActor)
	}

	stored := storedPolicy(t, s, ack.ID)

	if _, err := policiesUpdateHandler(deps)(ctx, PolicyUpdateInput{ID: ack.ID, Description: strPtr("edited")}, p); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := probe.event(t, "policy.updated")
	if updated.Actor != wantActor || updated.TenantID != "t1" || updated.EntityID != ack.ID {
		t.Errorf("update event = %+v", updated)
	}
	if b, ok := updated.Before.(*policy.Policy); !ok || !reflect.DeepEqual(b, stored) {
		t.Errorf("update before = %#v, want the stored policy %#v", updated.Before, stored)
	}
	if ent, ok := updated.Entity.(*policy.Policy); !ok || ent.Description != "edited" || ent.Version != stored.Version+1 {
		t.Errorf("update entity = %#v", updated.Entity)
	}
	if !probe.hasTyped("policy.updated") {
		t.Error("the typed OnPolicyUpdated hook did not fire")
	}

	afterUpdate := storedPolicy(t, s, ack.ID)
	if _, err := policiesSetActiveHandler(deps)(ctx, PolicySetActiveInput{ID: ack.ID, Active: true}, p); err != nil {
		t.Fatalf("setActive: %v", err)
	}
	// Two "policy.updated" events now; the second is setActive's.
	probe.mu.Lock()
	var updates []plugin.Event
	for _, e := range probe.events {
		if e.Action == "policy.updated" {
			updates = append(updates, e)
		}
		if e.Action == "policy.activated" || e.Action == "policy.deactivated" {
			t.Errorf("setActive emitted %q, which REST has no vocabulary for", e.Action)
		}
	}
	probe.mu.Unlock()
	if len(updates) != 2 {
		t.Fatalf("got %d policy.updated events after setActive, want 2", len(updates))
	}
	act := updates[1]
	if b, ok := act.Before.(*policy.Policy); !ok || !reflect.DeepEqual(b, afterUpdate) {
		t.Errorf("setActive before = %#v, want the stored policy", act.Before)
	}
	if ent, ok := act.Entity.(*policy.Policy); !ok || !ent.IsActive {
		t.Errorf("setActive entity = %#v, want the activated policy", act.Entity)
	}

	beforeDelete := storedPolicy(t, s, ack.ID)
	if _, err := policiesDeleteHandler(deps)(ctx, PolicyDeleteInput{ID: ack.ID}, p); err != nil {
		t.Fatalf("delete: %v", err)
	}
	del := probe.event(t, "policy.deleted")
	if del.Actor != wantActor || del.TenantID != "t1" || del.EntityID != ack.ID {
		t.Errorf("delete event = %+v", del)
	}
	if b, ok := del.Before.(*policy.Policy); !ok || !reflect.DeepEqual(b, beforeDelete) {
		t.Errorf("delete before = %#v, want the stored policy", del.Before)
	}
	if !probe.hasTyped("policy.deleted") {
		t.Error("the typed OnPolicyDeleted hook did not fire")
	}
}
