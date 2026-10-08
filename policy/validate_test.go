package policy

import (
	"strings"
	"testing"
)

func TestValidateCondition_UnknownOperator(t *testing.T) {
	err := ValidateCondition(Condition{Field: "subject.role", Operator: "bogus", Value: "x"})
	if err == nil {
		t.Fatal("expected error for unknown operator")
	}
}

func TestValidateCondition_KnownOperators(t *testing.T) {
	for _, op := range []Operator{
		OpEquals, OpNotEquals, OpIn, OpNotIn, OpContains, OpStartsWith, OpEndsWith,
		OpGreaterThan, OpLessThan, OpGTE, OpLTE, OpExists, OpNotExists,
	} {
		t.Run(string(op), func(t *testing.T) {
			var value any = "x"
			if op == OpIn || op == OpNotIn {
				value = []any{"x"}
			}
			err := ValidateCondition(Condition{Field: "subject.role", Operator: op, Value: value})
			if err != nil {
				t.Fatalf("expected %s to validate, got %v", op, err)
			}
		})
	}
}

func TestValidateCondition_FieldPrefix(t *testing.T) {
	tests := []struct {
		field string
		want  bool
	}{
		{"subject.role", true},
		{"resource.owner", true},
		{"context.ip", true},
		{"action", true},
		{"action.name", true},
		{"bogus.field", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			err := ValidateCondition(Condition{Field: tc.field, Operator: OpEquals, Value: "x"})
			if (err == nil) != tc.want {
				t.Fatalf("field %q: got err=%v, want valid=%v", tc.field, err, tc.want)
			}
		})
	}
}

func TestValidateCondition_Regex(t *testing.T) {
	if err := ValidateCondition(Condition{Field: "subject.id", Operator: OpRegex, Value: "^u-[0-9]+$"}); err != nil {
		t.Fatalf("expected valid regex to pass, got %v", err)
	}
	if err := ValidateCondition(Condition{Field: "subject.id", Operator: OpRegex, Value: "("}); err == nil {
		t.Fatal("expected invalid regex to fail")
	}
	long := strings.Repeat("a", 513)
	if err := ValidateCondition(Condition{Field: "subject.id", Operator: OpRegex, Value: long}); err == nil {
		t.Fatal("expected over-length regex to fail")
	}
	exactly512 := strings.Repeat("a", 512)
	if err := ValidateCondition(Condition{Field: "subject.id", Operator: OpRegex, Value: exactly512}); err != nil {
		t.Fatalf("expected exactly-512-char regex to pass, got %v", err)
	}
}

func TestValidateCondition_CIDR(t *testing.T) {
	if err := ValidateCondition(Condition{Field: "context.ip", Operator: OpIPInCIDR, Value: "10.0.0.0/8"}); err != nil {
		t.Fatalf("expected valid CIDR to pass, got %v", err)
	}
	if err := ValidateCondition(Condition{Field: "context.ip", Operator: OpIPInCIDR, Value: "not-a-cidr"}); err == nil {
		t.Fatal("expected invalid CIDR to fail")
	}
	if err := ValidateCondition(Condition{Field: "context.ip", Operator: OpIPInCIDR, Value: []string{"10.0.0.0/8", "bad"}}); err == nil {
		t.Fatal("expected one bad CIDR in a list to fail")
	}
	if err := ValidateCondition(Condition{Field: "context.ip", Operator: OpIPInCIDR, Value: []any{"10.0.0.0/8", "192.168.0.0/16"}}); err != nil {
		t.Fatalf("expected valid CIDR list ([]any) to pass, got %v", err)
	}
}

func TestValidateCondition_Time(t *testing.T) {
	if err := ValidateCondition(Condition{Field: "context.now", Operator: OpTimeAfter, Value: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatalf("expected valid RFC3339 time to pass, got %v", err)
	}
	if err := ValidateCondition(Condition{Field: "context.now", Operator: OpTimeBefore, Value: "not-a-time"}); err == nil {
		t.Fatal("expected invalid time to fail")
	}
	if err := ValidateCondition(Condition{Field: "context.now", Operator: OpTimeAfter, Value: 12345}); err == nil {
		t.Fatal("expected non-string time value to fail")
	}
}

func TestValidate_Effect(t *testing.T) {
	if err := Validate(&Policy{Effect: EffectAllow}); err != nil {
		t.Fatalf("expected allow effect to pass, got %v", err)
	}
	if err := Validate(&Policy{Effect: EffectDeny}); err != nil {
		t.Fatalf("expected deny effect to pass, got %v", err)
	}
	if err := Validate(&Policy{Effect: "bogus"}); err == nil {
		t.Fatal("expected unknown effect to fail")
	}
}

func TestValidate_PropagatesConditionErrors(t *testing.T) {
	p := &Policy{
		Effect: EffectAllow,
		Conditions: []Condition{
			{Field: "subject.id", Operator: OpEquals, Value: "x"},
			{Field: "bad field", Operator: OpEquals, Value: "x"},
		},
	}
	if err := Validate(p); err == nil {
		t.Fatal("expected error for bad condition field")
	}
}

func TestValidate_Nil(t *testing.T) {
	if err := Validate(nil); err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func TestValidateCondition_InAndNotInNeedAList(t *testing.T) {
	for _, op := range []Operator{OpIn, OpNotIn} {
		for _, v := range []any{"10.0.0.1", "a, b", float64(2), true, nil, map[string]any{"a": 1}} {
			err := ValidateCondition(Condition{Field: "context.ip", Operator: op, Value: v})
			if err == nil || !strings.Contains(err.Error(), "needs a list") {
				t.Errorf("%s %#v: err = %v, want a needs-a-list error", op, v, err)
			}
		}
		for _, v := range []any{[]any{"a"}, []string{"a"}, []int{1}, [2]string{"a", "b"}, []any{}} {
			if err := ValidateCondition(Condition{Field: "context.ip", Operator: op, Value: v}); err != nil {
				t.Errorf("%s %#v: %v, want it to validate", op, v, err)
			}
		}
	}
}
