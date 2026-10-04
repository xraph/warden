package policy

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// maxRegexLength bounds the size of a policy's regex condition pattern.
// Unbounded patterns are a ReDoS and resource-exhaustion risk when they
// come from tenant-supplied policy data.
const maxRegexLength = 512

var knownOperators = map[Operator]struct{}{
	OpEquals:      {},
	OpNotEquals:   {},
	OpIn:          {},
	OpNotIn:       {},
	OpContains:    {},
	OpStartsWith:  {},
	OpEndsWith:    {},
	OpGreaterThan: {},
	OpLessThan:    {},
	OpGTE:         {},
	OpLTE:         {},
	OpExists:      {},
	OpNotExists:   {},
	OpIPInCIDR:    {},
	OpTimeAfter:   {},
	OpTimeBefore:  {},
	OpRegex:       {},
}

// validFieldPrefixes are the condition field namespaces a policy condition
// may reference. "action" is allowed bare (matching action.name in the
// evaluator) or with a trailing segment.
var validFieldPrefixes = []string{"subject.", "resource.", "context."}

// ValidateCondition checks that a condition is well-formed:
//   - Operator is one of the known Operator constants.
//   - Field starts with "subject.", "resource.", "context." or is
//     "action"/"action.<x>".
//   - An in or not_in value is a list (any slice or array). The evaluator
//     refuses anything else, so a policy holding one fails closed.
//   - A regex condition's pattern compiles and is at most 512 characters.
//   - Every CIDR in an ip_in_cidr condition parses.
//   - time_after/time_before values parse as RFC3339.
func ValidateCondition(c Condition) error {
	if _, ok := knownOperators[c.Operator]; !ok {
		return fmt.Errorf("policy: unknown condition operator %q", c.Operator)
	}
	if !validConditionField(c.Field) {
		return fmt.Errorf("policy: condition field %q must start with subject., resource., context., or be action", c.Field)
	}

	switch c.Operator {
	case OpIn, OpNotIn:
		if !isList(c.Value) {
			return fmt.Errorf("policy: %s needs a list of values, got %T", c.Operator, c.Value)
		}
	case OpRegex:
		pattern := fmt.Sprint(c.Value)
		if len(pattern) > maxRegexLength {
			return fmt.Errorf("policy: regex condition pattern exceeds %d characters", maxRegexLength)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("policy: invalid regex pattern %q: %w", pattern, err)
		}
	case OpIPInCIDR:
		if err := validateCIDRValue(c.Value); err != nil {
			return err
		}
	case OpTimeAfter, OpTimeBefore:
		if err := validateTimeValue(c.Value); err != nil {
			return err
		}
	}
	return nil
}

// isList is the evaluator's test for an in or not_in value (inSlice in
// evaluator.go): any slice or array, whatever its element type.
// TestValidateConditionAgreesWithTheEvaluatorOnLists holds the two together.
func isList(v any) bool {
	k := reflect.ValueOf(v).Kind()
	return k == reflect.Slice || k == reflect.Array
}

func validConditionField(field string) bool {
	if field == "action" || strings.HasPrefix(field, "action.") {
		return true
	}
	for _, prefix := range validFieldPrefixes {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

func validateCIDRValue(v any) error {
	var cidrs []string
	switch t := v.(type) {
	case string:
		cidrs = []string{t}
	case []string:
		cidrs = t
	case []any:
		for _, item := range t {
			cidrs = append(cidrs, fmt.Sprint(item))
		}
	default:
		return fmt.Errorf("policy: ip_in_cidr value must be a string or list of strings, got %T", v)
	}
	if len(cidrs) == 0 {
		return fmt.Errorf("policy: ip_in_cidr requires at least one CIDR")
	}
	for _, c := range cidrs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("policy: invalid CIDR %q: %w", c, err)
		}
	}
	return nil
}

func validateTimeValue(v any) error {
	switch t := v.(type) {
	case time.Time:
		return nil
	case string:
		if _, err := time.Parse(time.RFC3339, t); err != nil {
			return fmt.Errorf("policy: invalid RFC3339 time %q: %w", t, err)
		}
		return nil
	default:
		return fmt.Errorf("policy: time condition value must be an RFC3339 string, got %T", v)
	}
}

// Validate checks a Policy's structural correctness: Effect must be "allow"
// or "deny", and every condition must pass ValidateCondition.
func Validate(p *Policy) error {
	if p == nil {
		return fmt.Errorf("policy: nil policy")
	}
	if p.Effect != EffectAllow && p.Effect != EffectDeny {
		return fmt.Errorf("policy: effect must be %q or %q, got %q", EffectAllow, EffectDeny, p.Effect)
	}
	for i, c := range p.Conditions {
		if err := ValidateCondition(c); err != nil {
			return fmt.Errorf("policy: condition[%d]: %w", i, err)
		}
	}
	return nil
}
