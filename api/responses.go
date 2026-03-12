package api

// CheckResponse is the response for an authorization check.
type CheckResponse struct {
	Allowed    bool        `json:"allowed" description:"Whether the request is allowed"`
	Decision   string      `json:"decision" description:"Decision code"`
	Reason     string      `json:"reason,omitempty" description:"Human-readable reason"`
	MatchedBy  []MatchInfo `json:"matched_by,omitempty" description:"Matched rules"`
	EvalTimeNs int64       `json:"eval_time_ns" description:"Evaluation time in nanoseconds"`
}

// MatchInfo identifies a matched rule.
type MatchInfo struct {
	Source string `json:"source" description:"Source model (rbac, rebac, abac)"`
	RuleID string `json:"rule_id,omitempty" description:"Rule identifier"`
	Detail string `json:"detail,omitempty" description:"Match detail"`
}

// BatchCheckResponse contains results for multiple checks.
type BatchCheckResponse struct {
	Results []CheckResponse `json:"results" description:"Check results in order"`
}

// ListResponse wraps a list of items with pagination metadata.
type ListResponse[T any] struct {
	Items  []T   `json:"items" description:"List of items"`
	Total  int64 `json:"total" description:"Total count"`
	Limit  int   `json:"limit" description:"Page size"`
	Offset int   `json:"offset" description:"Page offset"`
}

// RoleListResponse wraps a list of roles.
type RoleListResponse struct {
	Body any `json:"roles" body:"" description:"List of roles"`
}

// PermissionListResponse wraps a list of permissions.
type PermissionListResponse struct {
	Body any `json:"permissions" body:"" description:"List of permissions"`
}

// AssignmentListResponse wraps a list of assignments.
type AssignmentListResponse struct {
	Body any `json:"assignments" body:"" description:"List of assignments"`
}

// SubjectRolesResponse wraps a list of role IDs for a subject.
type SubjectRolesResponse struct {
	Body any `json:"role_ids" body:"" description:"List of role IDs"`
}

// RelationListResponse wraps a list of relation tuples.
type RelationListResponse struct {
	Body any `json:"relations" body:"" description:"List of relations"`
}

// PolicyListResponse wraps a list of policies.
type PolicyListResponse struct {
	Body any `json:"policies" body:"" description:"List of policies"`
}

// ResourceTypeListResponse wraps a list of resource types.
type ResourceTypeListResponse struct {
	Body any `json:"resource_types" body:"" description:"List of resource types"`
}

// CheckLogListResponse wraps a list of check log entries.
type CheckLogListResponse struct {
	Body any `json:"check_logs" body:"" description:"List of check logs"`
}
