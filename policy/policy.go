// Package policy defines the ABAC Policy entity with conditions and operators.
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

// Policy defines an attribute-based access control rule.
type Policy struct {
	ID          id.PolicyID    `json:"id" db:"id"`
	TenantID    string         `json:"tenant_id" db:"tenant_id"`
	AppID       string         `json:"app_id" db:"app_id"`
	Name        string         `json:"name" db:"name"`
	Description string         `json:"description,omitempty" db:"description"`
	Effect      Effect         `json:"effect" db:"effect"`
	Priority    int            `json:"priority" db:"priority"`
	IsActive    bool           `json:"is_active" db:"is_active"`
	Version     int            `json:"version" db:"version"`
	Subjects    []SubjectMatch `json:"subjects" db:"-"`
	Actions     []string       `json:"actions" db:"-"`
	Resources   []string       `json:"resources" db:"-"`
	Conditions  []Condition    `json:"conditions,omitempty" db:"-"`
	Metadata    map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
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
	TenantID string `json:"tenant_id,omitempty"`
	Effect   Effect `json:"effect,omitempty"`
	IsActive *bool  `json:"is_active,omitempty"`
	Search   string `json:"search,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}
