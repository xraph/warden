// Package checklog defines the check audit log Entry entity.
package checklog

import (
	"time"

	"github.com/xraph/warden/id"
)

// MatchRef records one rule that contributed to a decision. It is the
// persisted form of the engine's in-memory match info: Source names the
// evaluator ("rbac", "abac", "rebac"), RuleID names the role, policy or
// tuple, and Detail carries a human-readable explanation.
type MatchRef struct {
	Source string `json:"source" db:"source"`
	RuleID string `json:"rule_id,omitempty" db:"rule_id"`
	Detail string `json:"detail,omitempty" db:"detail"`
}

// Entry is a single authorization check audit record.
//
// An auditor reading one row should be able to reconstruct the decision
// without replaying the check, which is why MatchedBy, Obligations and the
// correlation IDs are stored rather than inferred.
type Entry struct {
	ID            id.CheckLogID  `json:"id" db:"id"`
	TenantID      string         `json:"tenant_id" db:"tenant_id"`
	NamespacePath string         `json:"namespace_path,omitempty" db:"namespace_path"`
	AppID         string         `json:"app_id" db:"app_id"`
	SubjectKind   string         `json:"subject_kind" db:"subject_kind"`
	SubjectID     string         `json:"subject_id" db:"subject_id"`
	Action        string         `json:"action" db:"action"`
	ResourceType  string         `json:"resource_type" db:"resource_type"`
	ResourceID    string         `json:"resource_id" db:"resource_id"`
	Decision      string         `json:"decision" db:"decision"`
	Reason        string         `json:"reason,omitempty" db:"reason"`
	MatchedBy     []MatchRef     `json:"matched_by,omitempty" db:"matched_by"`
	Obligations   []string       `json:"obligations,omitempty" db:"obligations"`
	EvalTimeNs    int64          `json:"eval_time_ns" db:"eval_time_ns"`
	RequestIP     string         `json:"request_ip,omitempty" db:"request_ip"`
	RequestID     string         `json:"request_id,omitempty" db:"request_id"`
	TraceID       string         `json:"trace_id,omitempty" db:"trace_id"`
	Cached        bool           `json:"cached" db:"cached"`
	Error         string         `json:"error,omitempty" db:"error"`
	Metadata      map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt     time.Time      `json:"created_at" db:"created_at"`
}

// QueryFilter contains filters for querying check logs.
type QueryFilter struct {
	TenantID        string     `json:"tenant_id,omitempty"`
	NamespacePath   *string    `json:"namespace_path,omitempty"`
	NamespacePrefix string     `json:"namespace_prefix,omitempty"`
	SubjectKind     string     `json:"subject_kind,omitempty"`
	SubjectID       string     `json:"subject_id,omitempty"`
	Action          string     `json:"action,omitempty"`
	ResourceType    string     `json:"resource_type,omitempty"`
	ResourceID      string     `json:"resource_id,omitempty"`
	Decision        string     `json:"decision,omitempty"`
	After           *time.Time `json:"after,omitempty"`
	Before          *time.Time `json:"before,omitempty"`
	Limit           int        `json:"limit,omitempty"`
	Offset          int        `json:"offset,omitempty"`
}
