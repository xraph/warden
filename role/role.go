// Package role defines the Role entity and its store interface for RBAC.
package role

import (
	"time"

	"github.com/xraph/warden/id"
)

// Role represents an authorization role that can be assigned to subjects.
type Role struct {
	ID          id.RoleID      `json:"id" db:"id"`
	TenantID    string         `json:"tenant_id" db:"tenant_id"`
	AppID       string         `json:"app_id" db:"app_id"`
	Name        string         `json:"name" db:"name"`
	Description string         `json:"description,omitempty" db:"description"`
	Slug        string         `json:"slug" db:"slug"`
	IsSystem    bool           `json:"is_system" db:"is_system"`
	IsDefault   bool           `json:"is_default" db:"is_default"`
	ParentID    *id.RoleID     `json:"parent_id,omitempty" db:"parent_id"`
	MaxMembers  int            `json:"max_members,omitempty" db:"max_members"`
	Metadata    map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// ListFilter contains filters for listing roles.
type ListFilter struct {
	TenantID  string     `json:"tenant_id,omitempty"`
	IsSystem  *bool      `json:"is_system,omitempty"`
	IsDefault *bool      `json:"is_default,omitempty"`
	ParentID  *id.RoleID `json:"parent_id,omitempty"`
	Search    string     `json:"search,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}
