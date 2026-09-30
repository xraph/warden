// policy_roundtrip.go: a fully populated policy survives every write and
// read path.
//
// Policy.Subjects, Actions, Resources, Conditions and Obligations are all
// db:"-", and each backend persists them its own way: postgres jsonb, sqlite
// JSON strings, mongo native arrays, memory deep copies. Every other case in
// this package builds policies with those five fields empty, so until this
// case the round-trip the dashboard's policy editor writes and reads back was
// proven on no backend.
//
// Numbers are chosen to be exact in float64, because a JSON round-trip
// returns them as float64. Integers beyond 2^53 are refused on write by the
// dashboard contract rather than tested here.
package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
)

const roundTripTenant = "rt-tenant"

func populatedPolicy() *policy.Policy {
	notBefore := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)
	return &policy.Policy{
		TenantID:      roundTripTenant,
		NamespacePath: "eng",
		Name:          "contractor-lockout",
		Description:   "every sub-entity populated",
		Effect:        policy.EffectDeny,
		Priority:      50,
		IsActive:      true,
		NotBefore:     &notBefore,
		NotAfter:      &notAfter,
		Version:       3,
		Subjects: []policy.SubjectMatch{
			{Role: "contractor"},
			{Kind: "user", ID: "usr_2f8a"},
			{Kind: "api_key"},
			{}, // an empty matcher is a real, stored shape: it matches everyone
		},
		Actions:   []string{"document:delete", "*"},
		Resources: []string{"document:*", "folder:root"},
		Conditions: []policy.Condition{
			{ID: id.NewConditionID(), Field: "context.ip", Operator: policy.OpNotIn, Value: []any{"10.0.0.1", "10.0.0.2"}},
			{ID: id.NewConditionID(), Field: "subject.mfa", Operator: policy.OpExists},
			{ID: id.NewConditionID(), Field: "resource.size", Operator: policy.OpGreaterThan, Value: 1024.5},
			{ID: id.NewConditionID(), Field: "subject.level", Operator: policy.OpGTE, Value: 9007199254740992.0},
			{ID: id.NewConditionID(), Field: "context.ip", Operator: policy.OpIPInCIDR, Value: []any{"10.0.0.0/8", "192.168.0.0/16"}},
			{ID: id.NewConditionID(), Field: "context.at", Operator: policy.OpTimeAfter, Value: "2026-06-01T09:00:00Z"},
			{ID: id.NewConditionID(), Field: "subject.email", Operator: policy.OpRegex, Value: `^[a-z]+@example\.com$`},
			{ID: id.NewConditionID(), Field: "action.name", Operator: policy.OpEquals, Value: "delete"},
			// Shapes a JSON comparison cannot tell apart from a driver's: a
			// mixed list, a bool, and a Go-written time.Time (a datetime on
			// mongo, an RFC3339 string on the JSON backends; the evaluator
			// accepts both).
			{ID: id.NewConditionID(), Field: "context.tier", Operator: policy.OpIn, Value: []any{"gold", 2.0, true}},
			{ID: id.NewConditionID(), Field: "subject.mfa", Operator: policy.OpEquals, Value: true},
			{ID: id.NewConditionID(), Field: "context.at", Operator: policy.OpTimeBefore, Value: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)},
		},
		Obligations: []string{"notify-security", "require-mfa"},
		Metadata:    map[string]any{"owner": "security", "ticket": 4412.0, "nested": map[string]any{"a": []any{"x", "y"}, "at": time.Date(2026, 6, 2, 3, 4, 5, 0, time.UTC)}},
		CreatedBy:   "usr_creator",
		UpdatedBy:   "usr_updater",
	}
}

// canonical renders a policy as the JSON value a reader sees, after
// normalising what backends legitimately differ on: timestamps the store
// assigns, time zones, and sub-second precision below a millisecond (mongo
// keeps milliseconds). Everything else must survive exactly.
func canonical(t *testing.T, p *policy.Policy) map[string]any {
	t.Helper()
	c := *p
	c.CreatedAt, c.UpdatedAt = time.Time{}, time.Time{}
	if c.NotBefore != nil {
		v := c.NotBefore.UTC().Truncate(time.Millisecond)
		c.NotBefore = &v
	}
	if c.NotAfter != nil {
		v := c.NotAfter.UTC().Truncate(time.Millisecond)
		c.NotAfter = &v
	}
	raw, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return out
}

// requirePlainValues fails if any condition value or metadata value, at any
// depth, is a type the engine's evaluator does not handle. The evaluator
// switches on exact types ([]any in inSlice and ipInCIDR, string and time.Time
// in parseTime), so a driver's named types (mongo's bson.A, bson.D,
// bson.DateTime) behave as "not a list" or "not a time" even though they
// marshal to identical JSON. That is exactly what a JSON comparison cannot
// see, so this walks the Go values themselves.
func requirePlainValues(t *testing.T, path string, p *policy.Policy) {
	t.Helper()
	for i, c := range p.Conditions {
		if bad := nonPlain(c.Value); bad != "" {
			t.Errorf("%s: condition %d (%s %s) value is not plain Go: %s", path, i, c.Field, c.Operator, bad)
		}
	}
	for k, v := range p.Metadata {
		if bad := nonPlain(v); bad != "" {
			t.Errorf("%s: metadata %q is not plain Go: %s", path, k, bad)
		}
	}
}

// nonPlain describes the first non-plain value inside v, or returns "".
func nonPlain(v any) string {
	switch x := v.(type) {
	case nil, string, bool, float64, float32,
		int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64,
		time.Time:
		return ""
	case []any:
		for i, item := range x {
			if bad := nonPlain(item); bad != "" {
				return fmt.Sprintf("[%d] %s", i, bad)
			}
		}
		return ""
	case map[string]any:
		for k, item := range x {
			if bad := nonPlain(item); bad != "" {
				return fmt.Sprintf("[%q] %s", k, bad)
			}
		}
		return ""
	}
	return fmt.Sprintf("%T", v)
}

// equivalenceRequests exercise every list, CIDR and time condition of
// populatedPolicy both ways, and every attribute condition at least once.
func equivalenceRequests() []*warden.CheckRequest {
	mk := func(ip, at, tier string, level, size float64, mfa bool, email, action string) *warden.CheckRequest {
		return &warden.CheckRequest{
			Subject:  warden.Subject{Kind: "user", ID: "usr_2f8a", Attributes: map[string]any{"level": level, "mfa": mfa, "email": email}},
			Action:   warden.Action{Name: action},
			Resource: warden.Resource{Type: "document", ID: "d1", Attributes: map[string]any{"size": size}},
			Context:  map[string]any{"ip": ip, "at": at, "tier": tier},
		}
	}
	return []*warden.CheckRequest{
		mk("10.0.0.1", "2026-06-10T00:00:00Z", "gold", 1, 10, true, "bob@example.com", "delete"),
		mk("8.8.8.8", "2026-05-01T00:00:00Z", "bronze", 9007199254740992, 2048, false, "nobody", "read"),
		mk("192.168.1.5", "2026-07-01T00:00:00Z", "2", 2, 2048, true, "eve@example.com", "delete"),
		mk("10.0.0.2", "2026-06-20T12:00:00Z", "true", 1, 1, false, "x", "read"),
		{Subject: warden.Subject{Kind: "user", ID: "usr_2f8a"}, Action: warden.Action{Name: "read"}, Resource: warden.Resource{Type: "document", ID: "d1"}},
	}
}

// oneCondition is p reduced to a single condition and open matchers, so the
// evaluator's answer is that condition's alone (it stops at the first false).
func oneCondition(p *policy.Policy, i int, effect policy.Effect) *policy.Policy {
	return &policy.Policy{Name: "one", Effect: effect, IsActive: true, Conditions: []policy.Condition{p.Conditions[i]}}
}

// applied runs one policy through warden's real evaluator, once per request.
func applied(t *testing.T, p *policy.Policy, reqs []*warden.CheckRequest) []bool {
	t.Helper()
	eval := warden.NewConditionEvaluator(func() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) })
	out := make([]bool, len(reqs))
	for i, req := range reqs {
		res, err := eval.Evaluate(context.Background(), []*policy.Policy{p}, req, nil)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		out[i] = res != nil
	}
	return out
}

// requireSameBehaviour proves the read-back policy DOES what the original
// does: each condition on its own, as an allow and as a deny, and then the
// whole policy with its real matchers, against requests chosen so each
// list, CIDR and time condition is exercised both ways.
func requireSameBehaviour(t *testing.T, path string, want, got *policy.Policy) {
	t.Helper()
	if len(want.Conditions) != len(got.Conditions) {
		t.Errorf("%s: %d conditions read back, want %d", path, len(got.Conditions), len(want.Conditions))
		return
	}
	reqs := equivalenceRequests()
	for i, c := range want.Conditions {
		for _, effect := range []policy.Effect{policy.EffectAllow, policy.EffectDeny} {
			w := applied(t, oneCondition(want, i, effect), reqs)
			g := applied(t, oneCondition(got, i, effect), reqs)
			if !reflect.DeepEqual(w, g) {
				t.Errorf("%s: condition %d (%s %s %v) as %s behaves differently after a round trip\n want applies %v\n  got applies %v",
					path, i, c.Field, c.Operator, c.Value, effect, w, g)
			}
			// The requests must tell a working condition from a broken one:
			// list, CIDR and time conditions must both apply and not apply.
			if effect == policy.EffectAllow {
				switch c.Operator {
				case policy.OpIn, policy.OpNotIn, policy.OpIPInCIDR, policy.OpTimeAfter, policy.OpTimeBefore:
					yes, no := false, false
					for _, a := range w {
						yes, no = yes || a, no || !a
					}
					if !yes || !no {
						t.Errorf("%s: the requests do not exercise condition %d (%s %s) both ways: %v", path, i, c.Field, c.Operator, w)
					}
				}
			}
		}
	}
	// Whole policy, as stored, with its real matchers and effect.
	if w, g := applied(t, want, reqs), applied(t, got, reqs); !reflect.DeepEqual(w, g) {
		t.Errorf("%s: the whole policy behaves differently after a round trip\n want %v\n  got %v", path, w, g)
	}
}

func requireSamePolicy(t *testing.T, path string, want, got *policy.Policy) {
	t.Helper()
	requirePlainValues(t, path, got)
	requireSameBehaviour(t, path, want, got)
	w, g := canonical(t, want), canonical(t, got)
	if !reflect.DeepEqual(w, g) {
		for k, wv := range w {
			if gv := g[k]; !reflect.DeepEqual(wv, gv) {
				t.Errorf("%s: field %q\n want %#v\n  got %#v", path, k, wv, gv)
			}
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				t.Errorf("%s: unexpected field %q = %#v", path, k, g[k])
			}
		}
	}
}

// RunPolicyRoundTripContract proves a populated policy survives create,
// update, and every read path the dashboard or the engine uses.
func RunPolicyRoundTripContract(t *testing.T, mk MakeStore) {
	t.Run("create then read through every path", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		want := populatedPolicy()
		if err := s.CreatePolicy(ctx, want); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}

		got, err := s.GetPolicy(ctx, roundTripTenant, want.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		requireSamePolicy(t, "GetPolicy", want, got)

		ns := "eng"
		listed, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: roundTripTenant, NamespacePath: &ns})
		if err != nil || len(listed) != 1 {
			t.Fatalf("ListPolicies: %d rows, err %v", len(listed), err)
		}
		requireSamePolicy(t, "ListPolicies", want, listed[0])

		// The engine's own read path. If this one drops a field the
		// dashboard would show a rule the engine never evaluates.
		active, err := s.ListActivePolicies(ctx, roundTripTenant, []string{"eng", ""})
		if err != nil || len(active) != 1 {
			t.Fatalf("ListActivePolicies: %d rows, err %v", len(active), err)
		}
		requireSamePolicy(t, "ListActivePolicies", want, active[0])
	})

	t.Run("update replaces every sub-entity and reads back", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		p := &policy.Policy{TenantID: roundTripTenant, NamespacePath: "eng", Name: "contractor-lockout", Effect: policy.EffectAllow, IsActive: true, Version: 1}
		if err := s.CreatePolicy(ctx, p); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}
		want := populatedPolicy()
		want.ID = p.ID
		if err := s.UpdatePolicy(ctx, want); err != nil {
			t.Fatalf("UpdatePolicy: %v", err)
		}
		// created_by is immutable on update in every backend (memory keeps
		// existing.CreatedBy; sqlite and postgres write policyUpdateColumns),
		// so the read-back carries the ORIGINAL creator, not want's.
		want.CreatedBy = p.CreatedBy
		got, err := s.GetPolicy(ctx, roundTripTenant, p.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		requireSamePolicy(t, "GetPolicy after UpdatePolicy", want, got)
	})

	t.Run("update can empty every sub-entity", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		p := populatedPolicy()
		if err := s.CreatePolicy(ctx, p); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}
		p.Subjects, p.Actions, p.Resources, p.Conditions, p.Obligations = nil, nil, nil, nil, nil
		if err := s.UpdatePolicy(ctx, p); err != nil {
			t.Fatalf("UpdatePolicy: %v", err)
		}
		got, err := s.GetPolicy(ctx, roundTripTenant, p.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		// An emptied list must read back as empty, not as the old values.
		// Whether it reads back nil or [] is backend-specific and both
		// mean "matches everything", so only the length is asserted.
		if len(got.Subjects)+len(got.Actions)+len(got.Resources)+len(got.Conditions)+len(got.Obligations) != 0 {
			t.Fatalf("emptied sub-entities came back: %+v", got)
		}
	})
}
