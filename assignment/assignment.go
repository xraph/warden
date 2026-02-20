// Package assignment defines the Assignment entity (role→subject binding).
package assignment

import (
	"time"

	"github.com/xraph/warden/id"
)

// Assignment binds a role to a subject within a tenant.
// Optionally scoped to a specific resource (resource-level RBAC).
type Assignment struct {
	ID           id.AssignmentID `json:"id" db:"id"`
	TenantID     string          `json:"tenant_id" db:"tenant_id"`
	AppID        string          `json:"app_id" db:"app_id"`
	RoleID       id.RoleID       `json:"role_id" db:"role_id"`
	SubjectKind  string          `json:"subject_kind" db:"subject_kind"`
	SubjectID    string          `json:"subject_id" db:"subject_id"`
	ResourceType string          `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   string          `json:"resource_id,omitempty" db:"resource_id"`
	ExpiresAt    *time.Time      `json:"expires_at,omitempty" db:"expires_at"`
	GrantedBy    string          `json:"granted_by,omitempty" db:"granted_by"`
	Metadata     map[string]any  `json:"metadata,omitempty" db:"metadata"`
	CreatedAt    time.Time       `json:"created_at" db:"created_at"`
}

// ListFilter contains filters for listing assignments.
type ListFilter struct {
	TenantID     string     `json:"tenant_id,omitempty"`
	RoleID       *id.RoleID `json:"role_id,omitempty"`
	SubjectKind  string     `json:"subject_kind,omitempty"`
	SubjectID    string     `json:"subject_id,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	ResourceID   string     `json:"resource_id,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Offset       int        `json:"offset,omitempty"`
}
