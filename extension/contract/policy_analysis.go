// policy_analysis.go: what a policy will actually do, decided before any
// check runs.
//
// Every rule here mirrors warden's evaluator (evaluator.go) and is tested
// against it in policy_analysis_test.go by running each case through
// warden.NewConditionEvaluator. If the engine changes, that test fails,
// rather than a page quietly describing behaviour the engine no longer has.
//
// Why this exists: nothing validates a policy on write (policy.Validate has
// no non-test caller, and the REST create stores whatever it is sent), and
// several shapes store fine while doing something other than what they read
// as. `context.ip not_in "10.0.0.0/8"` with a string instead of a list is
// always true, so on a deny it denies everyone. `gt` against a non-number is
// always false. `action.verb` never resolves, so `neq` on it is always true.
package contract

import (
	"fmt"
	"math"
	"net"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	"github.com/xraph/warden/policy"
)

// ConditionProblem is a condition's outcome when it does not depend on the
// check being made.
type ConditionProblem string

const (
	ProblemNone        ConditionProblem = ""
	ProblemThrows      ConditionProblem = "throws"      // evaluation errors: a deny fails closed, an allow is skipped
	ProblemAlwaysFalse ConditionProblem = "alwaysFalse" // the policy can never apply
	ProblemAlwaysTrue  ConditionProblem = "alwaysTrue"  // the condition restricts nothing
)

// ConditionReason says why a condition's outcome is fixed.
type ConditionReason string

const (
	ReasonNone              ConditionReason = ""
	ReasonUnknownOperator   ConditionReason = "unknownOperator"
	ReasonInvalidRegex      ConditionReason = "invalidRegex"
	ReasonUnresolvableField ConditionReason = "unresolvableField"
	ReasonNotAList          ConditionReason = "notAList"
	ReasonEmptyList         ConditionReason = "emptyList"
	ReasonNotANumber        ConditionReason = "notANumber"
	ReasonNoValidCIDR       ConditionReason = "noValidCIDR"
	ReasonNotATime          ConditionReason = "notATime"
	ReasonAlwaysPresent     ConditionReason = "alwaysPresent"
	ReasonMatchesAnything   ConditionReason = "matchesAnything"
)

// knownOperators is the evaluator's switch in evaluateCondition. Anything
// else falls to its default case, which returns an error.
var knownOperators = map[policy.Operator]struct{}{
	policy.OpEquals: {}, policy.OpNotEquals: {}, policy.OpIn: {}, policy.OpNotIn: {},
	policy.OpContains: {}, policy.OpStartsWith: {}, policy.OpEndsWith: {},
	policy.OpGreaterThan: {}, policy.OpLessThan: {}, policy.OpGTE: {}, policy.OpLTE: {},
	policy.OpExists: {}, policy.OpNotExists: {}, policy.OpIPInCIDR: {},
	policy.OpTimeAfter: {}, policy.OpTimeBefore: {}, policy.OpRegex: {},
}

// fieldResolves mirrors resolveField: only subject.<x>, resource.<x>,
// action.name and context.<x> ever produce a value. Bare "action" and
// "action.<anything but name>" pass policy.ValidateCondition and never
// resolve, which is a disagreement inside warden this contract compensates
// for.
//
// An empty suffix on subject, resource and context ("context.") is NOT
// unresolvable: resolveField looks up the attribute named "", which a caller
// can set, so the outcome depends on the check and no fixed outcome can be
// claimed. "action." is different, because only action.name resolves there.
func fieldResolves(field string) bool {
	prefix, suffix, ok := strings.Cut(field, ".")
	if !ok {
		return false
	}
	switch prefix {
	case "subject", "resource", "context":
		return true
	case "action":
		return suffix == "name"
	}
	return false
}

// alwaysPresentFields are the fields resolveField returns as a plain string on
// every request, so the value is never nil, even when the string is empty.
// Every other resolvable field is an attribute or context lookup and can be
// nil. Being present fixes only exists and not_exists on these. Check
// refusing some of them when empty fixes neq "" as well (requiredFields
// below). Apart from those, and from values that match any string, every
// operator on them depends on what the check carries.
var alwaysPresentFields = map[string]struct{}{
	"subject.kind": {}, "subject.id": {},
	"resource.type": {}, "resource.id": {},
	"action.name": {},
}

// requiredFields are the fields Engine.Check refuses to evaluate when empty
// (prepareCheck: subject ID, action name, resource type). Check and Explain
// are the only engine paths that evaluate policies, and both refuse first,
// so on every check warden evaluates these are never "". This holds for the
// engine's own evaluation; a caller that runs an Evaluator directly, or a
// BeforeCheck plugin that rewrites the request, is outside it.
var requiredFields = map[string]struct{}{
	"subject.id": {}, "action.name": {}, "resource.type": {},
}

// matchEveryRegex is the set of anchored patterns recognised as matching
// every string. Patterns with no anchor or other empty-width assertion are
// judged by regexMatchesEverything instead. "^.*$" is deliberately absent:
// without (?s) the dot does not match a newline, so it fails on a value
// containing one. Each entry here has an empty match on every string: "^"
// at the start, "$" at the end (without (?m) it is the end of the text,
// which every string has), "^.*" at the start and ".*$" at the end.
var matchEveryRegex = map[string]struct{}{"^": {}, "$": {}, "^.*": {}, ".*$": {}}

// regexMatchesEverything reports whether pattern, compiled as the evaluator
// compiles it, matches every string. It is true for the entries in
// matchEveryRegex, and for any pattern that has no empty-width assertion
// (^, $, \A, \z, \b, \B) and matches the empty string: such a pattern's empty
// match does not depend on what surrounds it, so MatchString finds it at the
// start of any value, newline or not. That covers "", ".*", "(?s).*", "(.*)"
// and "a*". Anything else that happens to match everything, "(?m)^.*$" for
// one, is not detected and is classified as request-dependent.
func regexMatchesEverything(pattern string) bool {
	if _, ok := matchEveryRegex[pattern]; ok {
		return true
	}
	tree, err := syntax.Parse(pattern, syntax.Perl) // what regexp.Compile parses with
	if err != nil || hasEmptyWidthAssertion(tree) {
		return false
	}
	re, err := regexp.Compile(pattern)
	return err == nil && re.MatchString("")
}

func hasEmptyWidthAssertion(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	for _, sub := range re.Sub {
		if hasEmptyWidthAssertion(sub) {
			return true
		}
	}
	return false
}

// listOf mirrors inSlice's accepted shapes: []string and []any, nothing
// else.
func listOf(v any) (items []string, isList bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, fmt.Sprint(item))
		}
		return out, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	out := make([]string, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out = append(out, fmt.Sprint(rv.Index(i).Interface()))
	}
	return out, true
}

// asNumber mirrors toFloat64 exactly, including the integer widths it does
// NOT accept (uint8, uint16).
func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
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
		return f, err == nil
	}
	return 0, false
}

// anyCIDRParses mirrors ipInCIDR: a string or list is accepted, an
// unparseable CIDR is skipped, and if none parse nothing can match.
func anyCIDRParses(v any) bool {
	var cidrs []string
	switch t := v.(type) {
	case string:
		cidrs = []string{t}
	default:
		items, ok := listOf(v)
		if !ok {
			return false
		}
		cidrs = items
	}
	for _, c := range cidrs {
		if _, _, err := net.ParseCIDR(c); err == nil {
			return true
		}
	}
	return false
}

// timeParses mirrors parseTime: a time.Time, or an RFC3339 string.
func timeParses(v any) bool {
	switch t := v.(type) {
	case time.Time:
		return true
	case string:
		_, err := time.Parse(time.RFC3339, t)
		return err == nil
	}
	return false
}

// nilOutcome is what evaluateCondition returns when the field resolved to
// nil, for the operators whose result then depends only on the stored
// value. It mirrors each case of evaluateCondition with actual = nil, where
// fmt.Sprint(nil) is "<nil>".
func nilOutcome(c policy.Condition) bool {
	actual := fmt.Sprint(nil)
	expected := fmt.Sprint(c.Value)
	switch c.Operator {
	case policy.OpEquals:
		return actual == expected
	case policy.OpNotEquals:
		return actual != expected
	case policy.OpIn, policy.OpNotIn:
		items, _ := listOf(c.Value)
		found := false
		for _, item := range items {
			if item == actual {
				found = true
			}
		}
		if c.Operator == policy.OpIn {
			return found
		}
		return !found
	case policy.OpContains:
		return strings.Contains(actual, expected)
	case policy.OpStartsWith:
		return strings.HasPrefix(actual, expected)
	case policy.OpEndsWith:
		return strings.HasSuffix(actual, expected)
	case policy.OpNotExists:
		return true
	case policy.OpRegex:
		re := regexp.MustCompile(expected) // callers check it compiles first
		return re.MatchString(actual)
	}
	// exists, gt, lt, gte, lte, ip_in_cidr, time_after, time_before are all
	// false for a nil actual.
	return false
}

// classifyCondition reports whether a condition's outcome is fixed, and why.
// The order matters: an unknown operator or an uncompilable regex throws
// regardless of the field, so those are checked first.
func classifyCondition(c policy.Condition) (ConditionProblem, ConditionReason) {
	if _, ok := knownOperators[c.Operator]; !ok {
		return ProblemThrows, ReasonUnknownOperator
	}
	if c.Operator == policy.OpRegex {
		if _, err := regexp.Compile(fmt.Sprint(c.Value)); err != nil {
			return ProblemThrows, ReasonInvalidRegex
		}
	}
	if c.Operator == policy.OpIn || c.Operator == policy.OpNotIn {
		if _, isList := listOf(c.Value); !isList {
			return ProblemThrows, ReasonNotAList
		}
	}
	if !fieldResolves(c.Field) {
		if nilOutcome(c) {
			return ProblemAlwaysTrue, ReasonUnresolvableField
		}
		return ProblemAlwaysFalse, ReasonUnresolvableField
	}
	switch c.Operator {
	case policy.OpContains, policy.OpStartsWith, policy.OpEndsWith:
		// strings.Contains, HasPrefix and HasSuffix are all true for "", on any
		// actual, including the "<nil>" a missing attribute prints as.
		if fmt.Sprint(c.Value) == "" {
			return ProblemAlwaysTrue, ReasonMatchesAnything
		}
	case policy.OpRegex:
		if regexMatchesEverything(fmt.Sprint(c.Value)) {
			return ProblemAlwaysTrue, ReasonMatchesAnything
		}
	}
	if _, ok := alwaysPresentFields[c.Field]; ok {
		switch c.Operator {
		case policy.OpExists:
			return ProblemAlwaysTrue, ReasonAlwaysPresent
		case policy.OpNotExists:
			return ProblemAlwaysFalse, ReasonAlwaysPresent
		}
	}
	// neq compares fmt.Sprint of both sides, and a required field is never
	// empty on a check warden evaluates. No reason fits: the field is not
	// absent, and the value does not match anything, so none is given.
	if _, ok := requiredFields[c.Field]; ok && c.Operator == policy.OpNotEquals && fmt.Sprint(c.Value) == "" {
		return ProblemAlwaysTrue, ReasonNone
	}
	switch c.Operator {
	case policy.OpIn, policy.OpNotIn:
		// A value that is not a list was classified as throwing above.
		if items, _ := listOf(c.Value); len(items) > 0 {
			return ProblemNone, ReasonNone
		}
		if c.Operator == policy.OpIn {
			return ProblemAlwaysFalse, ReasonEmptyList
		}
		return ProblemAlwaysTrue, ReasonEmptyList
	case policy.OpGreaterThan, policy.OpLessThan, policy.OpGTE, policy.OpLTE:
		n, ok := asNumber(c.Value)
		if !ok {
			return ProblemAlwaysFalse, ReasonNotANumber
		}
		// compareNumbers gives (0, true) when either side is NaN, because
		// neither < nor > holds. So gt and lt are false against NaN, but gte
		// and lte are TRUE for any numeric actual and false for the rest:
		// request-dependent, left unclassified. Infinities are not fixed
		// either: lt "+Inf" holds for every finite actual.
		if math.IsNaN(n) && (c.Operator == policy.OpGreaterThan || c.Operator == policy.OpLessThan) {
			return ProblemAlwaysFalse, ReasonNotANumber
		}
	case policy.OpIPInCIDR:
		if !anyCIDRParses(c.Value) {
			return ProblemAlwaysFalse, ReasonNoValidCIDR
		}
	case policy.OpTimeAfter, policy.OpTimeBefore:
		if !timeParses(c.Value) {
			return ProblemAlwaysFalse, ReasonNotATime
		}
	}
	return ProblemNone, ReasonNone
}

// Policy states. "never" is a window whose end precedes its start: under
// EffectiveAt it cannot be in effect at any instant.
const (
	StateActive    = "active"
	StateInactive  = "inactive"
	StateScheduled = "scheduled"
	StateExpired   = "expired"
	StateNever     = "never"
)

func policyState(p *policy.Policy, now time.Time) string {
	switch {
	case !p.IsActive:
		return StateInactive
	case p.NotBefore != nil && p.NotAfter != nil && p.NotAfter.Before(*p.NotBefore):
		return StateNever
	case p.NotBefore != nil && now.Before(*p.NotBefore):
		return StateScheduled
	case p.NotAfter != nil && now.After(*p.NotAfter):
		return StateExpired
	}
	return StateActive
}

// policyAnalysis is everything the dashboard shows about a policy that the
// stored fields do not say directly.
type policyAnalysis struct {
	State        string
	FailsClosed  bool // a deny that applies as if its conditions from DecidingCondition on were met
	NeverApplies bool
	// DecidingCondition is the index of the condition that makes the policy
	// fail closed or never apply, or -1.
	DecidingCondition     int
	Problems              []ConditionProblem
	Reasons               []ConditionReason
	SubjectsUnrestricted  bool
	ActionsUnrestricted   bool
	ResourcesUnrestricted bool
	// MatchesEverything is true when the policy applies to every check: all
	// three matchers are unrestricted AND the conditions always hold. It
	// describes the rule's shape, so it does not depend on State.
	MatchesEverything bool
	HasRoleMatcher    bool
}

// analysePolicy walks the conditions in evaluation order.
// evaluateConditions stops at the first false and at the first error, so
// the FIRST condition with a fixed false or error outcome decides, and a
// condition that merely depends on the check cannot rescue a later one.
func analysePolicy(p *policy.Policy, now time.Time) policyAnalysis {
	a := policyAnalysis{
		State:             policyState(p, now),
		DecidingCondition: -1,
		Problems:          make([]ConditionProblem, len(p.Conditions)),
		Reasons:           make([]ConditionReason, len(p.Conditions)),
	}
	for i, c := range p.Conditions {
		a.Problems[i], a.Reasons[i] = classifyCondition(c)
	}
	for i, pr := range a.Problems {
		if pr == ProblemThrows {
			a.DecidingCondition = i
			if p.Effect == policy.EffectAllow {
				a.NeverApplies = true
			} else {
				a.FailsClosed = true // anything but exactly "allow" is a deny
			}
			break
		}
		if pr == ProblemAlwaysFalse {
			a.DecidingCondition = i
			a.NeverApplies = true
			break
		}
	}

	a.SubjectsUnrestricted = len(p.Subjects) == 0
	for _, s := range p.Subjects {
		if s.Kind == "" && s.ID == "" && s.Role == "" {
			a.SubjectsUnrestricted = true
		}
		if s.Role != "" {
			a.HasRoleMatcher = true
		}
	}
	a.ActionsUnrestricted = len(p.Actions) == 0 || anyMatchesEveryValue(p.Actions)
	a.ResourcesUnrestricted = len(p.Resources) == 0 || anyMatchesEveryValue(p.Resources)
	a.MatchesEverything = a.SubjectsUnrestricted && a.ActionsUnrestricted && a.ResourcesUnrestricted &&
		conditionsAlwaysHold(p.Effect, a.Problems)
	return a
}

// conditionsAlwaysHold reports whether, for a policy that passes its matchers,
// the conditions are met on every check. It walks them in evaluation order,
// as evaluateConditions does: an always-true condition changes nothing, and
// the first other condition decides. A throw on a deny is met (the engine
// fails closed and treats the conditions as satisfied); a throw on an allow
// skips the policy, an always-false condition fails, and a condition that
// depends on the check holds for some checks and not others. Reaching the
// end, including having no conditions at all, means they always hold.
func conditionsAlwaysHold(effect policy.Effect, problems []ConditionProblem) bool {
	for _, pr := range problems {
		switch pr {
		case ProblemAlwaysTrue:
			continue
		case ProblemThrows:
			return effect != policy.EffectAllow
		default:
			return false
		}
	}
	return true
}

// matchesEveryValue reports whether matchGlob (matcher.go) accepts every
// value for pattern. Its first two checks are the only unconditional ones:
// "*", and the full wildcards "*:*" and "*.*". Every other pattern either
// needs a literal prefix (a trailing ":*", ".*" or "*" keeps the text before
// the star) or is compared for equality, so it restricts. matchesAction and
// matchesResource both go through matchGlob, and the extra
// matchGlob(r, Resource.Type) path in matchesResource uses the same function,
// so the set is the same for actions and resources.
func matchesEveryValue(pattern string) bool {
	return pattern == "*" || pattern == "*:*" || pattern == "*.*"
}

func anyMatchesEveryValue(patterns []string) bool {
	for _, p := range patterns {
		if matchesEveryValue(p) {
			return true
		}
	}
	return false
}
