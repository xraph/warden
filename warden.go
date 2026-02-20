// Package warden provides composable permissions and authorization for Go.
//
// Warden supports RBAC (role-based), ABAC (attribute-based), and ReBAC
// (relationship-based) authorization models individually or combined.
// It is tenant-scoped by default via forge.Scope and integrates with the
// Forge ecosystem for audit logging, feature flags, and async jobs.
//
//	eng, err := warden.NewEngine(
//	    warden.WithStore(memStore),
//	)
//	result, err := eng.Check(ctx, &warden.CheckRequest{
//	    Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "user_123"},
//	    Action:   warden.Action{Name: "read"},
//	    Resource: warden.Resource{Type: "document", ID: "doc_456"},
//	})
package warden

// SubjectKind identifies the type of actor making an authorization request.
type SubjectKind string

const (
	// SubjectUser represents a human user.
	SubjectUser SubjectKind = "user"

	// SubjectAPIKey represents an API key (e.g., from Keysmith).
	SubjectAPIKey SubjectKind = "api_key"

	// SubjectService represents a service-to-service caller.
	SubjectService SubjectKind = "service"

	// SubjectServiceAcct represents a service account.
	SubjectServiceAcct SubjectKind = "service_acct"
)

// Subject represents an actor in an authorization check.
type Subject struct {
	Kind       SubjectKind    `json:"kind"`
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Resource represents the target of an authorization check.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Action represents what the subject wants to do.
type Action struct {
	Name string `json:"name"`
}

// CheckRequest is the input to an authorization check.
type CheckRequest struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// CheckResult is the outcome of an authorization check.
type CheckResult struct {
	Allowed    bool        `json:"allowed"`
	Decision   Decision    `json:"decision"`
	Reason     string      `json:"reason,omitempty"`
	MatchedBy  []MatchInfo `json:"matched_by,omitempty"`
	EvalTimeNs int64       `json:"eval_time_ns"`
}

// Decision is the authorization outcome.
type Decision string

const (
	// DecisionAllow means the request is permitted.
	DecisionAllow Decision = "allow"

	// DecisionDeny means the request is denied (generic).
	DecisionDeny Decision = "deny"

	// DecisionDenyExplicit means an explicit deny policy matched.
	DecisionDenyExplicit Decision = "deny_explicit"

	// DecisionDenyDefault means no matching allow rule was found.
	DecisionDenyDefault Decision = "deny_default"

	// DecisionDenyNoRoles means the subject has no roles assigned.
	DecisionDenyNoRoles Decision = "deny_no_roles"

	// DecisionDenyNoPerms means no role grants the required permission.
	DecisionDenyNoPerms Decision = "deny_no_perms"

	// DecisionDenyCondition means an ABAC condition blocked the request.
	DecisionDenyCondition Decision = "deny_condition"

	// DecisionDenyRelation means no matching relation was found.
	DecisionDenyRelation Decision = "deny_relation"
)

// MatchInfo describes what rule matched during evaluation.
type MatchInfo struct {
	Source string `json:"source"` // "rbac", "abac", "rebac"
	RuleID string `json:"rule_id,omitempty"`
	Detail string `json:"detail,omitempty"`
}
