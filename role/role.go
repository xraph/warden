// Package role defines the Role entity and its store interface for RBAC.
package role

import (
	"time"

	"github.com/xraph/warden/id"
)

// Role represents an authorization role that can be assigned to subjects.
//
// Inheritance is expressed by ParentSlug, the slug of another role in the
// same tenant and namespace. Slugs are stable, human-readable, and unique
// per (tenant_id, namespace_path, slug) — making role hierarchies declarable
// in source-controlled config without knowing typeids upfront.
//
// NamespacePath locates the role within the tenant's namespace tree (e.g.
// "engineering/platform"). Empty string is the tenant root. Resolution at
// Check time considers a subject's roles at the request's namespace and
// every ancestor of that namespace (cascading scope inheritance).
type Role struct {
	ID            id.RoleID      `json:"id" db:"id"`
	TenantID      string         `json:"tenant_id" db:"tenant_id"`
	NamespacePath string         `json:"namespace_path,omitempty" db:"namespace_path"`
	AppID         string         `json:"app_id" db:"app_id"`
	Name          string         `json:"name" db:"name"`
	Description   string         `json:"description,omitempty" db:"description"`
	Slug          string         `json:"slug" db:"slug"`
	IsSystem      bool           `json:"is_system" db:"is_system"`
	IsDefault     bool           `json:"is_default" db:"is_default"`
	ParentSlug    string         `json:"parent_slug,omitempty" db:"parent_slug"`
	MaxMembers    int            `json:"max_members,omitempty" db:"max_members"`
	Metadata      map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt     time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at" db:"updated_at"`
}

// ListFilter contains filters for listing roles.
//
// NamespacePath does an exact-match filter; NamespacePrefix matches all
// descendants under a path (e.g. "engineering/" matches "engineering",
// "engineering/platform", "engineering/platform/sre").
type ListFilter struct {
	TenantID        string  `json:"tenant_id,omitempty"`
	NamespacePath   *string `json:"namespace_path,omitempty"`
	NamespacePrefix string  `json:"namespace_prefix,omitempty"`
	IsSystem        *bool   `json:"is_system,omitempty"`
	IsDefault       *bool   `json:"is_default,omitempty"`
	ParentSlug      *string `json:"parent_slug,omitempty"`
	Search          string  `json:"search,omitempty"`
	Limit           int     `json:"limit,omitempty"`
	Offset          int     `json:"offset,omitempty"`
}
