// Package policy defines the Policy entity used for ABAC and PBAC evaluation.
//
// ABAC (attribute-based) is the basic match: condition predicates over
// subject / resource / action / context attributes.
//
// PBAC (policy-based) adds:
//   - Time-bound policies via NotBefore/NotAfter — policies that only fire
//     within an effective window. Outside the window the policy is treated
//     as if IsActive=false. Useful for scheduled feature flags, temporary
//     access grants, audit-mode rollouts, and incident-response rules
//     ("freeze production deploys until 2026-06-01").
//   - Obligations: named actions emitted when a policy matches. The engine
//     records every obligation that fired in CheckResult.Obligations and
//     emits a plugin hook (PolicyObligationFired) so audit / Chronicle /
//     notification systems can react. Examples: "audit-log", "require-mfa",
//     "notify-security", "step-up-auth".
package policy

import (
	"time"

	"github.com/xraph/warden/id"
)

// Effect is the policy outcome — allow or deny.
type Effect string

const (
	// EffectAllow permits matching requests.
	EffectAllow Effect = "allow"

	// EffectDeny blocks matching requests.
	EffectDeny Effect = "deny"
)

// Policy defines an attribute-based / policy-based access-control rule.
//
// NamespacePath locates the policy within the tenant's namespace tree. A
// policy at namespace N applies to checks in N and all descendants.
//
// NotBefore and NotAfter define the policy's effective window. A nil
// pointer means "no bound on that side". Outside the window the policy is
// skipped exactly as if IsActive were false, regardless of the IsActive
// flag — IsActive is the manual override; NotBefore/NotAfter are the
// schedule.
//
// Obligations is a list of named actions the policy emits when it
// matches. The engine records them in CheckResult.Obligations and fires
// the PolicyObligationFired plugin hook for each. Obligations don't
// change the allow/deny decision; they're side-effect signals consumed by
// audit, notification, and step-up-auth systems.
type Policy struct {
	ID            id.PolicyID    `json:"id" db:"id"`
	TenantID      string         `json:"tenant_id" db:"tenant_id"`
	NamespacePath string         `json:"namespace_path,omitempty" db:"namespace_path"`
	AppID         string         `json:"app_id" db:"app_id"`
	Name          string         `json:"name" db:"name"`
	Description   string         `json:"description,omitempty" db:"description"`
	Effect        Effect         `json:"effect" db:"effect"`
	Priority      int            `json:"priority" db:"priority"`
	IsActive      bool           `json:"is_active" db:"is_active"`
	NotBefore     *time.Time     `json:"not_before,omitempty" db:"not_before"`
	NotAfter      *time.Time     `json:"not_after,omitempty" db:"not_after"`
	Obligations   []string       `json:"obligations,omitempty" db:"-"`
	Version       int            `json:"version" db:"version"`
	Subjects      []SubjectMatch `json:"subjects" db:"-"`
	Actions       []string       `json:"actions" db:"-"`
	Resources     []string       `json:"resources" db:"-"`
	Conditions    []Condition    `json:"conditions,omitempty" db:"-"`
	Metadata      map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt     time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at" db:"updated_at"`
}

// EffectiveAt reports whether the policy is active at instant t. Returns
// false if IsActive is false, NotBefore is in the future, or NotAfter is
// in the past. Inputs may be the zero time (treated as "no bound").
func (p *Policy) EffectiveAt(t time.Time) bool {
	if !p.IsActive {
		return false
	}
	if p.NotBefore != nil && t.Before(*p.NotBefore) {
		return false
	}
	if p.NotAfter != nil && t.After(*p.NotAfter) {
		return false
	}
	return true
}

// SubjectMatch defines which subjects a policy applies to.
// Kind and ID are plain strings to avoid import cycles with the root warden package.
type SubjectMatch struct {
	Kind string `json:"kind,omitempty"` // SubjectKind as string
	ID   string `json:"id,omitempty"`
	Role string `json:"role,omitempty"`
}

// Condition is a single attribute predicate within a policy.
type Condition struct {
	ID       id.ConditionID `json:"id" db:"id"`
	Field    string         `json:"field"`
	Operator Operator       `json:"operator"`
	Value    any            `json:"value"`
}

// Operator is a comparison operator for conditions.
type Operator string

const (
	// OpEquals checks for equality.
	OpEquals Operator = "eq"

	// OpNotEquals checks for inequality.
	OpNotEquals Operator = "neq"

	// OpIn checks if a value is in a set.
	OpIn Operator = "in"

	// OpNotIn checks if a value is not in a set.
	OpNotIn Operator = "not_in"

	// OpContains checks if a string contains a substring.
	OpContains Operator = "contains"

	// OpStartsWith checks if a string starts with a prefix.
	OpStartsWith Operator = "starts_with"

	// OpEndsWith checks if a string ends with a suffix.
	OpEndsWith Operator = "ends_with"

	// OpGreaterThan checks if a value is greater than another.
	OpGreaterThan Operator = "gt"

	// OpLessThan checks if a value is less than another.
	OpLessThan Operator = "lt"

	// OpGTE checks if a value is greater than or equal to another.
	OpGTE Operator = "gte"

	// OpLTE checks if a value is less than or equal to another.
	OpLTE Operator = "lte"

	// OpExists checks if a field is present.
	OpExists Operator = "exists"

	// OpNotExists checks if a field is absent.
	OpNotExists Operator = "not_exists"

	// OpIPInCIDR checks if an IP address falls within a CIDR range.
	OpIPInCIDR Operator = "ip_in_cidr"

	// OpTimeAfter checks if a time is after a threshold.
	OpTimeAfter Operator = "time_after"

	// OpTimeBefore checks if a time is before a threshold.
	OpTimeBefore Operator = "time_before"

	// OpRegex checks if a value matches a regular expression.
	OpRegex Operator = "regex"
)

// ListFilter contains filters for listing policies.
type ListFilter struct {
	TenantID        string  `json:"tenant_id,omitempty"`
	NamespacePath   *string `json:"namespace_path,omitempty"`
	NamespacePrefix string  `json:"namespace_prefix,omitempty"`
	Effect          Effect  `json:"effect,omitempty"`
	IsActive        *bool   `json:"is_active,omitempty"`
	Search          string  `json:"search,omitempty"`
	Limit           int     `json:"limit,omitempty"`
	Offset          int     `json:"offset,omitempty"`
}
