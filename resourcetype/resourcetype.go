// Package resourcetype defines the ResourceType entity for ReBAC schema definitions.
package resourcetype

import (
	"time"

	"github.com/xraph/warden/id"
)

// ResourceType defines the schema for a resource kind — valid relations
// and permission derivation rules (OpenFGA-style authorization model).
//
// NamespacePath locates the resource type within the tenant's namespace
// tree. Resource types defined at an ancestor namespace are visible from
// descendants.
type ResourceType struct {
	ID            id.ResourceTypeID `json:"id" db:"id"`
	TenantID      string            `json:"tenant_id" db:"tenant_id"`
	NamespacePath string            `json:"namespace_path,omitempty" db:"namespace_path"`
	AppID         string            `json:"app_id" db:"app_id"`
	Name          string            `json:"name" db:"name"`
	Description   string            `json:"description,omitempty" db:"description"`
	Relations     []RelationDef     `json:"relations" db:"-"`
	Permissions   []PermissionDef   `json:"permissions" db:"-"`
	Metadata      map[string]any    `json:"metadata,omitempty" db:"metadata"`
	CreatedAt     time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at" db:"updated_at"`
}

// RelationDef defines a valid relation for a resource type.
type RelationDef struct {
	Name            string   `json:"name"`
	AllowedSubjects []string `json:"allowed_subjects"`
}

// PermissionDef defines a derived permission expression.
type PermissionDef struct {
	Name       string `json:"name"`
	Expression string `json:"expression"` // e.g., "viewer or editor or owner"
}

// ListFilter contains filters for listing resource types.
type ListFilter struct {
	TenantID        string  `json:"tenant_id,omitempty"`
	NamespacePath   *string `json:"namespace_path,omitempty"`
	NamespacePrefix string  `json:"namespace_prefix,omitempty"`
	Search          string  `json:"search,omitempty"`
	Limit           int     `json:"limit,omitempty"`
	Offset          int     `json:"offset,omitempty"`
}
