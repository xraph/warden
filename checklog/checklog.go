// Package checklog defines the check audit log Entry entity.
package checklog

import (
	"time"

	"github.com/xraph/warden/id"
)

// Entry is a single authorization check audit record.
type Entry struct {
	ID           id.CheckLogID  `json:"id" db:"id"`
	TenantID     string         `json:"tenant_id" db:"tenant_id"`
	AppID        string         `json:"app_id" db:"app_id"`
	SubjectKind  string         `json:"subject_kind" db:"subject_kind"`
	SubjectID    string         `json:"subject_id" db:"subject_id"`
	Action       string         `json:"action" db:"action"`
	ResourceType string         `json:"resource_type" db:"resource_type"`
	ResourceID   string         `json:"resource_id" db:"resource_id"`
	Decision     string         `json:"decision" db:"decision"`
	Reason       string         `json:"reason,omitempty" db:"reason"`
	EvalTimeNs   int64          `json:"eval_time_ns" db:"eval_time_ns"`
	RequestIP    string         `json:"request_ip,omitempty" db:"request_ip"`
	Metadata     map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt    time.Time      `json:"created_at" db:"created_at"`
}

// QueryFilter contains filters for querying check logs.
type QueryFilter struct {
	TenantID     string     `json:"tenant_id,omitempty"`
	SubjectKind  string     `json:"subject_kind,omitempty"`
	SubjectID    string     `json:"subject_id,omitempty"`
	Action       string     `json:"action,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	ResourceID   string     `json:"resource_id,omitempty"`
	Decision     string     `json:"decision,omitempty"`
	After        *time.Time `json:"after,omitempty"`
	Before       *time.Time `json:"before,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Offset       int        `json:"offset,omitempty"`
}
