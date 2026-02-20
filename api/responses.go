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
