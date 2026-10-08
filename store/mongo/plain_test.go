package mongo

import (
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/warden/policy"
)

// These run without a database: they pin the type conversion that the
// integration round trip proves against a real server.

func TestPlainValueConvertsDriverTypes(t *testing.T) {
	when := time.Date(2026, 6, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"an array", bson.A{"a", "b"}, []any{"a", "b"}},
		{"an empty array", bson.A{}, []any{}},
		{"a document", bson.D{{Key: "k", Value: "v"}}, map[string]any{"k": "v"}},
		{"a bson.M", bson.M{"k": "v"}, map[string]any{"k": "v"}},
		{"a datetime", bson.NewDateTimeFromTime(when), when},
		{"nested", bson.D{{Key: "l", Value: bson.A{bson.D{{Key: "t", Value: bson.NewDateTimeFromTime(when)}}, "x"}}},
			map[string]any{"l": []any{map[string]any{"t": when}, "x"}}},
		{"an array inside a plain slice", []any{bson.A{"a"}}, []any{[]any{"a"}}},
		{"a string is untouched", "s", "s"},
		{"a float is untouched", 1.5, 1.5},
		{"an int32 is untouched", int32(3), int32(3)},
		{"nil is untouched", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := plainValue(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestPlainValueGivesUTCTimes(t *testing.T) {
	// bson.DateTime.Time() is in the local zone. The engine compares instants,
	// but a stable zone keeps read-backs comparable across backends.
	got := plainValue(bson.NewDateTimeFromTime(time.Date(2026, 6, 2, 3, 4, 5, 0, time.FixedZone("x", 3600)))).(time.Time)
	if got.Location() != time.UTC {
		t.Fatalf("location %v", got.Location())
	}
}

func TestPolicyFromModelHandsBackPlainValues(t *testing.T) {
	m := &policyModel{
		ID: "",
		Conditions: []policy.Condition{
			{Field: "context.ip", Operator: policy.OpNotIn, Value: bson.A{"10.0.0.1"}},
			{Field: "context.at", Operator: policy.OpTimeAfter, Value: bson.NewDateTimeFromTime(time.Unix(0, 0))},
		},
		Metadata: map[string]any{"nested": bson.D{{Key: "a", Value: bson.A{"x"}}}},
	}
	p := policyFromModel(m)
	if _, ok := p.Conditions[0].Value.([]any); !ok {
		t.Fatalf("list condition is %T, want []any", p.Conditions[0].Value)
	}
	if _, ok := p.Conditions[1].Value.(time.Time); !ok {
		t.Fatalf("time condition is %T, want time.Time", p.Conditions[1].Value)
	}
	if _, ok := p.Metadata["nested"].(map[string]any); !ok {
		t.Fatalf("metadata is %T, want map[string]any", p.Metadata["nested"])
	}
	// The model is not modified in place.
	if _, ok := m.Conditions[0].Value.(bson.A); !ok {
		t.Fatalf("the stored model was rewritten: %T", m.Conditions[0].Value)
	}
	if got := policyFromModel(&policyModel{}); got.Conditions != nil || got.Metadata != nil {
		t.Fatalf("nil stayed nil expected, got %#v %#v", got.Conditions, got.Metadata)
	}
}
