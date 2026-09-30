// policy_validate.go: refuse, on write, the policy shapes that store fine
// but cannot behave the way they read.
//
// Nothing below the contract does this: policy.Validate has no non-test
// caller. And policy.ValidateCondition on its own is not enough, because it
// accepts fields the evaluator never resolves (bare "action", "action.x")
// and says nothing about the always-true and always-false shapes
// classifyCondition finds.
package contract

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// PolicySubject mirrors policy.SubjectMatch. Its three fields are AND-ed.
type PolicySubject struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
	Role string `json:"role,omitempty"`
}

// PolicyCondition is one condition on the wire. Value's JSON type follows
// the operator: a list for in, not_in and ip_in_cidr (ip_in_cidr also
// accepts one string), a number for gt, lt, gte and lte, an RFC3339 string
// for time_after and time_before, absent for exists and not_exists, and a
// string otherwise.
type PolicyCondition struct {
	ID       string `json:"id,omitempty"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value,omitempty"`
}

// PolicyDraft is the editable body of a policy.
type PolicyDraft struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Effect      string            `json:"effect"`
	Priority    int               `json:"priority"`
	NotBefore   string            `json:"notBefore,omitempty"`
	NotAfter    string            `json:"notAfter,omitempty"`
	Subjects    []PolicySubject   `json:"subjects"`
	Actions     []string          `json:"actions"`
	Resources   []string          `json:"resources"`
	Conditions  []PolicyCondition `json:"conditions"`
	Obligations []string          `json:"obligations"`
}

// ConditionIssue marks one condition row.
type ConditionIssue struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}

// PolicyIssues is every reason a draft cannot be saved. Fields is keyed by
// wire name: name, effect, window, subjects, actions, resources,
// obligations. Conditions carries one entry per bad row, so a page can mark
// the exact row.
type PolicyIssues struct {
	Fields     map[string]string `json:"fields"`
	Conditions []ConditionIssue  `json:"conditions"`
}

func (i PolicyIssues) empty() bool { return len(i.Fields) == 0 && len(i.Conditions) == 0 }

// draftParts says which parts of a draft are being written. An update
// validates only what it changes, so a policy stored with a bad condition
// before this validation existed can still have its description edited.
type draftParts struct {
	name, effect, window, subjects, actions, resources, conditions, obligations bool
}

var allParts = draftParts{true, true, true, true, true, true, true, true}

// maxExactInteger is the largest magnitude float64 holds exactly. A number
// past it does not survive a JSON round-trip through postgres or sqlite,
// and eq compares through fmt.Sprint, so the stored condition would
// silently stop matching.
const maxExactInteger = 1 << 53

// validSubjectKinds is already declared in handlers_assignments.go (plan
// 2b) with exactly warden's closed set. Reuse it; do not redeclare it.

func collectPolicyIssues(d PolicyDraft, parts draftParts) PolicyIssues {
	issues := PolicyIssues{Fields: map[string]string{}, Conditions: []ConditionIssue{}}
	if parts.name && strings.TrimSpace(d.Name) == "" {
		issues.Fields["name"] = "A policy needs a name."
	}
	if parts.effect && d.Effect != string(policy.EffectAllow) && d.Effect != string(policy.EffectDeny) {
		issues.Fields["effect"] = `Effect must be "allow" or "deny".`
	}
	if parts.window {
		if msg := windowIssue(d.NotBefore, d.NotAfter); msg != "" {
			issues.Fields["window"] = msg
		}
	}
	if parts.subjects {
		for _, raw := range d.Subjects {
			// Trimmed as it is stored (storedSubject), so a subject that is
			// only whitespace is refused rather than stored as the empty
			// matcher that matches everyone.
			s := storedSubject(raw)
			if s.Kind == "" && s.ID == "" && s.Role == "" {
				issues.Fields["subjects"] = "An empty subject matcher matches everyone. To mean everyone, remove every subject instead."
				break
			}
			if _, ok := validSubjectKinds[s.Kind]; s.Kind != "" && !ok {
				issues.Fields["subjects"] = fmt.Sprintf("Subject kind %q is not one warden checks. Use user, api_key, service or service_acct.", s.Kind)
				break
			}
		}
	}
	if parts.actions && hasEmptyEntry(d.Actions) {
		issues.Fields["actions"] = "An entry is empty."
	}
	if parts.resources && hasEmptyEntry(d.Resources) {
		issues.Fields["resources"] = "An entry is empty."
	}
	if parts.obligations && hasEmptyEntry(d.Obligations) {
		issues.Fields["obligations"] = "An entry is empty."
	}
	if parts.conditions {
		for i, c := range d.Conditions {
			if msg := conditionIssue(c); msg != "" {
				issues.Conditions = append(issues.Conditions, ConditionIssue{Index: i, Message: msg})
			}
		}
	}
	return issues
}

// hasEmptyEntry reports whether any entry is blank. A blank action or resource
// entry matches nothing useful, and a blank obligation names nothing to do.
func hasEmptyEntry(list []string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == "" {
			return true
		}
	}
	return false
}

func windowIssue(notBefore, notAfter string) string {
	var nb, na time.Time
	var err error
	if notBefore != "" {
		if nb, err = time.Parse(time.RFC3339, notBefore); err != nil {
			return "The start is not an RFC3339 time."
		}
	}
	if notAfter != "" {
		if na, err = time.Parse(time.RFC3339, notAfter); err != nil {
			return "The end is not an RFC3339 time."
		}
	}
	if notBefore != "" && notAfter != "" && !na.After(nb) {
		return "The end must be after the start."
	}
	return ""
}

// storedCondition is the one place a wire condition becomes the condition
// that is stored. Validation and storage both go through it, so what is
// validated is exactly what is stored: the field is trimmed here, once.
func storedCondition(c PolicyCondition) policy.Condition {
	return policy.Condition{Field: strings.TrimSpace(c.Field), Operator: policy.Operator(c.Operator), Value: c.Value}
}

// storedSubject is the one place a wire subject becomes the subject that is
// stored, trimmed once, for the same reason storedCondition is.
func storedSubject(s PolicySubject) policy.SubjectMatch {
	return policy.SubjectMatch{Kind: strings.TrimSpace(s.Kind), ID: strings.TrimSpace(s.ID), Role: strings.TrimSpace(s.Role)}
}

// toPolicySubjects converts every subject through storedSubject. The result
// is never nil, so an empty list is stored as one.
func toPolicySubjects(in []PolicySubject) []policy.SubjectMatch {
	out := make([]policy.SubjectMatch, 0, len(in))
	for _, s := range in {
		out = append(out, storedSubject(s))
	}
	return out
}

// trimmedList trims every entry, as hasEmptyEntry judged them. The result is
// never nil.
func trimmedList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

// conditionIssue returns why one condition cannot be saved, or "".
func conditionIssue(c PolicyCondition) string {
	pc := storedCondition(c)
	// classifyCondition first: its messages say what the condition would DO,
	// which is the useful thing to tell an operator.
	problem, reason := classifyCondition(pc)
	switch {
	case reason == ReasonUnknownOperator:
		return fmt.Sprintf("%q is not an operator warden knows, so this condition would fail every check.", c.Operator)
	case reason == ReasonInvalidRegex:
		return "This pattern does not compile, so this condition would fail every check."
	case reason == ReasonUnresolvableField:
		return fmt.Sprintf("Warden never gives %q a value, so this condition would always be %t. Use subject., resource., context., or action.name.", pc.Field, problem == ProblemAlwaysTrue)
	case reason == ReasonAlwaysPresent:
		return fmt.Sprintf("Warden always gives %q a value, even an empty one, so this condition would always be %t.", pc.Field, problem == ProblemAlwaysTrue)
	case reason == ReasonMatchesAnything:
		return "This matches every value, so this condition is always true and restricts nothing."
	case isComparison(pc.Operator) && nonFinite(pc.Value):
		return "The value is not a finite number."
	case reason == ReasonNotAList:
		return "This operator needs a list of values."
	case reason == ReasonEmptyList && problem == ProblemAlwaysFalse:
		return "The list is empty, so this condition is never met and the policy never applies."
	case reason == ReasonEmptyList:
		return "The list is empty, so this condition restricts nothing."
	case reason == ReasonNotANumber:
		return "This operator compares numbers, and the value is not one."
	case reason == ReasonNoValidCIDR:
		return "None of these parse as a network like 10.0.0.0/8."
	case reason == ReasonNotATime:
		return "The value must be an RFC3339 time, like 2026-06-01T09:00:00Z."
	}
	if err := policy.ValidateCondition(pc); err != nil {
		return strings.TrimPrefix(err.Error(), "policy: ")
	}
	if n, ok := largestMagnitude(c.Value); ok && n > maxExactInteger {
		if isComparison(pc.Operator) {
			return "Numbers above 9007199254740992 lose precision when stored, and a comparison reads a string as a number too, so use a smaller number."
		}
		return "Numbers above 9007199254740992 lose precision when stored. Store it as a string instead."
	}
	return ""
}

func isComparison(op policy.Operator) bool {
	switch op {
	case policy.OpGreaterThan, policy.OpLessThan, policy.OpGTE, policy.OpLTE:
		return true
	}
	return false
}

// nonFinite reports whether v reads as NaN or an infinity, as a number or as
// a string strconv.ParseFloat accepts. gt and lt against NaN never hold, and
// an infinite bound is a comparison nobody means to write.
func nonFinite(v any) bool {
	n, ok := asNumber(v)
	return ok && (math.IsNaN(n) || math.IsInf(n, 0))
}

// largestMagnitude finds the largest absolute numeric value in a value or
// a list of values.
func largestMagnitude(v any) (float64, bool) {
	if items, ok := v.([]any); ok {
		var best float64
		found := false
		for _, item := range items {
			if n, ok := largestMagnitude(item); ok {
				found = true
				best = math.Max(best, n)
			}
		}
		return best, found
	}
	switch n := v.(type) {
	case float64:
		return math.Abs(n), true
	case float32:
		return math.Abs(float64(n)), true
	case int:
		return math.Abs(float64(n)), true
	case int64:
		return math.Abs(float64(n)), true
	}
	return 0, false
}

// issuesError turns issues into the BAD_REQUEST a page renders row by row.
func issuesError(i PolicyIssues) error {
	if i.empty() {
		return nil
	}
	return &dashcontract.Error{
		Code:    dashcontract.CodeBadRequest,
		Message: fmt.Sprintf("This policy cannot be saved: %d condition(s) and %d field(s) need fixing.", len(i.Conditions), len(i.Fields)),
		Details: map[string]any{"fields": i.Fields, "conditions": i.Conditions},
	}
}

// toPolicyConditions keeps a condition id the caller sent, and gives every
// other condition a fresh one, as the REST create does.
func toPolicyConditions(in []PolicyCondition) []policy.Condition {
	out := make([]policy.Condition, 0, len(in))
	for _, c := range in {
		cid, err := id.ParseConditionID(c.ID)
		if err != nil {
			cid = id.NewConditionID()
		}
		sc := storedCondition(c)
		sc.ID = cid
		out = append(out, sc)
	}
	return out
}

// PolicyValidateResponse is policies.validate's reply.
type PolicyValidateResponse struct {
	Valid bool `json:"valid"`
	PolicyIssues
}

func policiesValidateHandler(deps Deps) func(ctx context.Context, in PolicyDraft, p dashcontract.Principal) (PolicyValidateResponse, error) {
	return func(ctx context.Context, in PolicyDraft, p dashcontract.Principal) (PolicyValidateResponse, error) {
		if err := requireEngine(deps); err != nil {
			return PolicyValidateResponse{}, err
		}
		if _, err := tenantFrom(p, deps); err != nil {
			return PolicyValidateResponse{}, err
		}
		issues := collectPolicyIssues(in, allParts)
		return PolicyValidateResponse{Valid: issues.empty(), PolicyIssues: issues}, nil
	}
}
