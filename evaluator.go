package warden

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/policy"
)

// Evaluator evaluates ABAC/PBAC policies against a check request.
//
// roleSlugs is the set of role slugs (direct and inherited) held by the
// requesting subject, resolved by the engine before evaluation. It powers
// role-scoped policy.SubjectMatch.Role matching: a policy naming
// {Role: "editor"} only applies to subjects holding a role with that slug.
type Evaluator interface {
	Evaluate(ctx context.Context, policies []*policy.Policy, req *CheckRequest, roleSlugs []string) (*CheckResult, error)
}

// DefaultEvaluator returns the built-in condition evaluator backed by the
// system wall clock.
func DefaultEvaluator() Evaluator { return NewConditionEvaluator(time.Now) }

// NewConditionEvaluator returns an Evaluator that uses the supplied clock
// for PBAC time-window evaluation (NotBefore / NotAfter). Pass time.Now
// for production; tests can pass a fixed-time function.
func NewConditionEvaluator(now func() time.Time) Evaluator {
	if now == nil {
		now = time.Now
	}
	return &conditionEvaluator{now: now, logger: log.NewNoopLogger()}
}

type conditionEvaluator struct {
	now    func() time.Time
	logger log.Logger
}

// setLogger lets the engine wire its configured logger into the default
// evaluator after options are applied (NewEngine constructs the default
// evaluator before WithLogger runs). Unexported: callers that supply their
// own Evaluator via WithEvaluator are unaffected.
func (e *conditionEvaluator) setLogger(l log.Logger) {
	if l != nil {
		e.logger = l
	}
}

func (e *conditionEvaluator) Evaluate(_ context.Context, policies []*policy.Policy, req *CheckRequest, roleSlugs []string) (*CheckResult, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	now := e.now()
	if now.IsZero() {
		now = time.Now()
	}

	sorted := sortPoliciesByPriority(policies)

	var bestDeny *CheckResult
	var bestAllow *CheckResult
	var allObligations []string

	for _, pol := range sorted {
		if !pol.EffectiveAt(now) {
			continue
		}

		if !e.matchesSubject(pol, req, roleSlugs) {
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
			if pol.Effect != policy.EffectAllow {
				// Fail closed: a deny policy whose condition couldn't be
				// evaluated still applies rather than silently opening up
				// access. Logged, because the deny it produces looks like
				// any other in the check log, and this one comes from a
				// broken condition rather than a met one.
				e.logger.Warn("warden: abac condition evaluation error, applying deny policy (fail closed)",
					log.String("policy", pol.Name),
					log.String("policy_id", pol.ID.String()),
					log.Error(err),
				)
				conditionsMet = true
			} else {
				e.logger.Warn("warden: abac condition evaluation error, skipping policy",
					log.String("policy", pol.Name),
					log.String("policy_id", pol.ID.String()),
					log.Error(err),
				)
				continue
			}
		}
		if !conditionsMet {
			continue
		}

		// Obligations fire on every matched policy, regardless of effect.
		// They are side-effect signals; the calling system decides what to do.
		allObligations = append(allObligations, pol.Obligations...)

		info := MatchInfo{
			Source: "abac",
			RuleID: pol.ID.String(),
			Detail: fmt.Sprintf("policy %q (%s)", pol.Name, pol.Effect),
		}

		// Anything that isn't an explicit allow is treated as deny:
		// defense in depth against an unvalidated/garbage Effect value.
		if pol.Effect != policy.EffectAllow {
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

	// Explicit deny always wins over allow. Obligations from every matched
	// policy (allow OR deny) flow through to the caller.
	if bestDeny != nil {
		bestDeny.Obligations = dedupeStrings(allObligations)
		return bestDeny, nil
	}
	if bestAllow != nil {
		bestAllow.Obligations = dedupeStrings(allObligations)
		return bestAllow, nil
	}

	return nil, nil
}

// sortPoliciesByPriority returns a new slice ordered by Priority descending,
// tie-broken by Name ascending for determinism. The input slice is not
// mutated.
func sortPoliciesByPriority(policies []*policy.Policy) []*policy.Policy {
	sorted := make([]*policy.Policy, len(policies))
	copy(sorted, policies)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		return sorted[i].Name < sorted[j].Name
	})
	return sorted
}

// dedupeStrings returns a new slice preserving first-occurrence order. Used
// for merging obligations from many matched policies; obligations are
// idempotent by name (the consumer dedupes the action it triggers).
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// contains reports whether want is present in list.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func (e *conditionEvaluator) matchesSubject(pol *policy.Policy, req *CheckRequest, roleSlugs []string) bool {
	return PolicySelectsSubject(pol, req.Subject.Kind, req.Subject.ID, roleSlugs)
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

// resolveField reads a condition field from the request. Under subject and
// resource, kind, type and id name the built-in fields and anything else
// names an attribute (see lookupAttribute for the attributes. spelling).
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
		return lookupAttribute(req.Subject.Attributes, parts[1])
	case "resource":
		if parts[1] == "type" {
			return req.Resource.Type
		}
		if parts[1] == "id" {
			return req.Resource.ID
		}
		return lookupAttribute(req.Resource.Attributes, parts[1])
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

// lookupAttribute reads key from a subject or resource attribute map. The
// docs and the DSL spell an attribute subject.attributes.<k>, or
// subject.attributes["<k>"] when <k> isn't a bare word, so key arrives here
// as attributes.<k> or attributes["<k>"]. When attrs has no key spelled that
// way literally, the <k> inside it is looked up instead. The literal key wins
// so a caller who really sends an attribute named "attributes.<k>" keeps
// getting it: no field that resolved to a value before resolves differently
// now, and only fields that used to resolve to nil change.
func lookupAttribute(attrs map[string]any, key string) any {
	if attrs == nil {
		return nil
	}
	if v, ok := attrs[key]; ok {
		return v
	}
	if k, ok := strings.CutPrefix(key, "attributes."); ok {
		return attrs[k]
	}
	if quoted, ok := strings.CutPrefix(key, "attributes["); ok {
		if quoted, ok = strings.CutSuffix(quoted, "]"); ok {
			if k, err := strconv.Unquote(quoted); err == nil {
				return attrs[k]
			}
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
		return inSlice(actual, expected)
	case policy.OpNotIn:
		found, err := inSlice(actual, expected)
		return !found, err
	case policy.OpContains:
		return strings.Contains(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	case policy.OpStartsWith:
		return strings.HasPrefix(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	case policy.OpEndsWith:
		return strings.HasSuffix(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	case policy.OpGreaterThan:
		cmp, ok := compareNumbers(actual, expected)
		return ok && cmp > 0, nil
	case policy.OpLessThan:
		cmp, ok := compareNumbers(actual, expected)
		return ok && cmp < 0, nil
	case policy.OpGTE:
		cmp, ok := compareNumbers(actual, expected)
		return ok && cmp >= 0, nil
	case policy.OpLTE:
		cmp, ok := compareNumbers(actual, expected)
		return ok && cmp <= 0, nil
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
		re, err := compiledRegex(fmt.Sprint(expected))
		if err != nil {
			return false, fmt.Errorf("%w: invalid regex %q: %w", ErrInvalidCondition, expected, err)
		}
		return re.MatchString(fmt.Sprint(actual)), nil
	default:
		return false, fmt.Errorf("%w: unknown operator %q", ErrInvalidCondition, op)
	}
}

// regexCache memoizes compiled regular expressions across Check calls,
// keyed by pattern source. Policies reuse the same handful of patterns
// across many checks, so this avoids recompiling on every evaluation.
var regexCache sync.Map // string -> *regexp.Regexp

func compiledRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Races are harmless here: two goroutines may compile the same pattern
	// concurrently; LoadOrStore just picks whichever won.
	actual, _ := regexCache.LoadOrStore(pattern, re)
	if cached, ok := actual.(*regexp.Regexp); ok {
		return cached, nil
	}
	return re, nil
}

// errNotAList is returned for an in or not_in whose stored value is not a
// list. Read as "never in it", a not_in would hold for every request and an
// in for none, so an allow would grant everyone and a deny would deny no one.
// As an error it fails closed: a deny applies, an allow is skipped.
var errNotAList = errors.New("in and not_in need a list of values")

func inSlice(actual, expected any) (bool, error) {
	s := fmt.Sprint(actual)
	switch v := expected.(type) {
	case []string:
		for _, item := range v {
			if item == s {
				return true, nil
			}
		}
		return false, nil
	case []any:
		for _, item := range v {
			if fmt.Sprint(item) == s {
				return true, nil
			}
		}
		return false, nil
	}
	// Any other slice or array ([]int, []float64, a driver's named slice
	// type) is still a list.
	rv := reflect.ValueOf(expected)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return false, fmt.Errorf("%w, got %T", errNotAList, expected)
	}
	for i := 0; i < rv.Len(); i++ {
		if fmt.Sprint(rv.Index(i).Interface()) == s {
			return true, nil
		}
	}
	return false, nil
}

// compareNumbers compares a and b numerically. The second return value is
// false ("not comparable") when either side is nil or cannot be parsed as a
// number, in which case the caller must treat the condition as unmet rather
// than guessing a comparison result from zero values.
func compareNumbers(a, b any) (int, bool) {
	fa, okA := toFloat64(a)
	fb, okB := toFloat64(b)
	if !okA || !okB {
		return 0, false
	}
	if fa < fb {
		return -1, true
	}
	if fa > fb {
		return 1, true
	}
	return 0, true
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
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
