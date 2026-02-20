package warden

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/xraph/warden/policy"
)

// Evaluator evaluates ABAC policies against a check request.
type Evaluator interface {
	Evaluate(ctx context.Context, policies []*policy.Policy, req *CheckRequest) (*CheckResult, error)
}

// DefaultEvaluator returns the built-in condition evaluator.
func DefaultEvaluator() Evaluator { return &conditionEvaluator{} }

type conditionEvaluator struct{}

func (e *conditionEvaluator) Evaluate(_ context.Context, policies []*policy.Policy, req *CheckRequest) (*CheckResult, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	var bestDeny *CheckResult
	var bestAllow *CheckResult

	for _, pol := range policies {
		if !pol.IsActive {
			continue
		}

		if !e.matchesSubject(pol, req) {
			continue
		}
		if !e.matchesAction(pol, req) {
			continue
		}
		if !e.matchesResource(pol, req) {
			continue
		}

		conditionsMet, err := e.evaluateConditions(pol.Conditions, req)
		if err != nil {
			return nil, fmt.Errorf("evaluate conditions for policy %s: %w", pol.Name, err)
		}
		if !conditionsMet {
			continue
		}

		info := MatchInfo{
			Source: "abac",
			RuleID: pol.ID.String(),
			Detail: fmt.Sprintf("policy %q (%s)", pol.Name, pol.Effect),
		}

		if pol.Effect == policy.EffectDeny {
			result := &CheckResult{
				Allowed:   false,
				Decision:  DecisionDenyExplicit,
				Reason:    fmt.Sprintf("denied by policy %q", pol.Name),
				MatchedBy: []MatchInfo{info},
			}
			if bestDeny == nil {
				bestDeny = result
			}
		} else {
			result := &CheckResult{
				Allowed:   true,
				Decision:  DecisionAllow,
				MatchedBy: []MatchInfo{info},
			}
			if bestAllow == nil {
				bestAllow = result
			}
		}
	}

	// Explicit deny always wins over allow.
	if bestDeny != nil {
		return bestDeny, nil
	}
	if bestAllow != nil {
		return bestAllow, nil
	}

	return nil, nil
}

func (e *conditionEvaluator) matchesSubject(pol *policy.Policy, req *CheckRequest) bool {
	if len(pol.Subjects) == 0 {
		return true // No subject filter means all subjects.
	}
	for _, sm := range pol.Subjects {
		if sm.Kind != "" && sm.Kind != string(req.Subject.Kind) {
			continue
		}
		if sm.ID != "" && sm.ID != req.Subject.ID {
			continue
		}
		return true
	}
	return false
}

func (e *conditionEvaluator) matchesAction(pol *policy.Policy, req *CheckRequest) bool {
	if len(pol.Actions) == 0 {
		return true
	}
	for _, a := range pol.Actions {
		if a == "*" || matchGlob(a, req.Action.Name) {
			return true
		}
	}
	return false
}

func (e *conditionEvaluator) matchesResource(pol *policy.Policy, req *CheckRequest) bool {
	if len(pol.Resources) == 0 {
		return true
	}
	target := req.Resource.Type + ":" + req.Resource.ID
	targetType := req.Resource.Type + ":*"
	for _, r := range pol.Resources {
		if r == "*" || r == target || r == targetType {
			return true
		}
		if matchGlob(r, target) || matchGlob(r, req.Resource.Type) {
			return true
		}
	}
	return false
}

func (e *conditionEvaluator) evaluateConditions(conditions []policy.Condition, req *CheckRequest) (bool, error) {
	for _, c := range conditions {
		val := resolveField(c.Field, req)
		ok, err := evaluateCondition(c.Operator, val, c.Value)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func resolveField(field string, req *CheckRequest) any {
	parts := strings.SplitN(field, ".", 2)
	if len(parts) < 2 {
		return nil
	}
	switch parts[0] {
	case "subject":
		if parts[1] == "kind" {
			return string(req.Subject.Kind)
		}
		if parts[1] == "id" {
			return req.Subject.ID
		}
		if req.Subject.Attributes != nil {
			return req.Subject.Attributes[parts[1]]
		}
	case "resource":
		if parts[1] == "type" {
			return req.Resource.Type
		}
		if parts[1] == "id" {
			return req.Resource.ID
		}
		if req.Resource.Attributes != nil {
			return req.Resource.Attributes[parts[1]]
		}
	case "action":
		if parts[1] == "name" {
			return req.Action.Name
		}
	case "context":
		if req.Context != nil {
			return req.Context[parts[1]]
		}
	}
	return nil
}

func evaluateCondition(op policy.Operator, actual, expected any) (bool, error) {
	switch op {
	case policy.OpEquals:
		return fmt.Sprint(actual) == fmt.Sprint(expected), nil
	case policy.OpNotEquals:
		return fmt.Sprint(actual) != fmt.Sprint(expected), nil
	case policy.OpIn:
		return inSlice(actual, expected), nil
	case policy.OpNotIn:
		return !inSlice(actual, expected), nil
	case policy.OpContains:
		return strings.Contains(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	case policy.OpStartsWith:
		return strings.HasPrefix(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	case policy.OpEndsWith:
		return strings.HasSuffix(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	case policy.OpGreaterThan:
		return compareNumbers(actual, expected) > 0, nil
	case policy.OpLessThan:
		return compareNumbers(actual, expected) < 0, nil
	case policy.OpGTE:
		return compareNumbers(actual, expected) >= 0, nil
	case policy.OpLTE:
		return compareNumbers(actual, expected) <= 0, nil
	case policy.OpExists:
		return actual != nil, nil
	case policy.OpNotExists:
		return actual == nil, nil
	case policy.OpIPInCIDR:
		return ipInCIDR(fmt.Sprint(actual), expected)
	case policy.OpTimeAfter:
		return timeCompare(actual, expected, true)
	case policy.OpTimeBefore:
		return timeCompare(actual, expected, false)
	case policy.OpRegex:
		re, err := regexp.Compile(fmt.Sprint(expected))
		if err != nil {
			return false, fmt.Errorf("%w: invalid regex %q: %w", ErrInvalidCondition, expected, err)
		}
		return re.MatchString(fmt.Sprint(actual)), nil
	default:
		return false, fmt.Errorf("%w: unknown operator %q", ErrInvalidCondition, op)
	}
}

func inSlice(actual, expected any) bool {
	s := fmt.Sprint(actual)
	switch v := expected.(type) {
	case []string:
		for _, item := range v {
			if item == s {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if fmt.Sprint(item) == s {
				return true
			}
		}
	}
	return false
}

func compareNumbers(a, b any) int {
	fa := toFloat64(a)
	fb := toFloat64(b)
	if fa < fb {
		return -1
	}
	if fa > fb {
		return 1
	}
	return 0
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case float32:
		return float64(n)
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err != nil {
			return 0
		}
		return f
	default:
		return 0
	}
}

func ipInCIDR(ipStr string, cidrVal any) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, nil
	}

	var cidrs []string
	switch v := cidrVal.(type) {
	case string:
		cidrs = []string{v}
	case []string:
		cidrs = v
	case []any:
		for _, item := range v {
			cidrs = append(cidrs, fmt.Sprint(item))
		}
	default:
		return false, nil
	}

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

func timeCompare(actual, expected any, after bool) (bool, error) {
	at, ok := parseTime(actual)
	if !ok {
		return false, nil
	}
	et, ok := parseTime(expected)
	if !ok {
		return false, nil
	}
	if after {
		return at.After(et), nil
	}
	return at.Before(et), nil
}

func parseTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		parsed, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return time.Time{}, false
		}
		return parsed, true
	default:
		return time.Time{}, false
	}
}
