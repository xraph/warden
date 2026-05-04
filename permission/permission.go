// Package permission defines the Permission entity and its store interface.
package permission

import (
	"time"

	"github.com/xraph/warden/id"
)

// Permission represents a specific action allowed on a resource type.
//
// NamespacePath locates the permission within the tenant's namespace tree.
// Empty string is the tenant root. Permissions defined at an ancestor
// namespace are visible from descendants.
type Permission struct {
	ID            id.PermissionID `json:"id" db:"id"`
	TenantID      string          `json:"tenant_id" db:"tenant_id"`
	NamespacePath string          `json:"namespace_path,omitempty" db:"namespace_path"`
	AppID         string          `json:"app_id" db:"app_id"`
	Name          string          `json:"name" db:"name"`
	Description   string          `json:"description,omitempty" db:"description"`
	Resource      string          `json:"resource" db:"resource"`
	Action        string          `json:"action" db:"action"`
	IsSystem      bool            `json:"is_system" db:"is_system"`
	Metadata      map[string]any  `json:"metadata,omitempty" db:"metadata"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`
}

// ListFilter contains filters for listing permissions.
type ListFilter struct {
	TenantID        string  `json:"tenant_id,omitempty"`
	NamespacePath   *string `json:"namespace_path,omitempty"`
	NamespacePrefix string  `json:"namespace_prefix,omitempty"`
	Resource        string  `json:"resource,omitempty"`
	Action          string  `json:"action,omitempty"`
	IsSystem        *bool   `json:"is_system,omitempty"`
	Search          string  `json:"search,omitempty"`
	Limit           int     `json:"limit,omitempty"`
	Offset          int     `json:"offset,omitempty"`
}
