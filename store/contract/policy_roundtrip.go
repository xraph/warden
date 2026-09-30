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
	"reflect"
	"testing"
	"time"

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
		},
		Obligations: []string{"notify-security", "require-mfa"},
		Metadata:    map[string]any{"owner": "security", "ticket": 4412.0, "nested": map[string]any{"a": []any{"x", "y"}}},
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

func requireSamePolicy(t *testing.T, path string, want, got *policy.Policy) {
	t.Helper()
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
