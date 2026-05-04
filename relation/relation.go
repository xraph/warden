// Package relation defines the Tuple entity for ReBAC (Zanzibar-style relations).
package relation

import (
	"time"

	"github.com/xraph/warden/id"
)

// Tuple represents a relationship between a subject and an object.
// Inspired by Google Zanzibar / SpiceDB / OpenFGA.
//
//	user:alice#member@group:engineering
//	document:readme#viewer@user:bob
//	folder:root#parent@document:readme
//
// NamespacePath partitions the relation space — a tuple at namespace N is
// only matched when checking inside N (no ancestor cascading for tuples,
// since they reference concrete object/subject pairs and cross-namespace
// matching would be semantically wrong).
type Tuple struct {
	ID              id.RelationID  `json:"id" db:"id"`
	TenantID        string         `json:"tenant_id" db:"tenant_id"`
	NamespacePath   string         `json:"namespace_path,omitempty" db:"namespace_path"`
	AppID           string         `json:"app_id" db:"app_id"`
	ObjectType      string         `json:"object_type" db:"object_type"`
	ObjectID        string         `json:"object_id" db:"object_id"`
	Relation        string         `json:"relation" db:"relation"`
	SubjectType     string         `json:"subject_type" db:"subject_type"`
	SubjectID       string         `json:"subject_id" db:"subject_id"`
	SubjectRelation string         `json:"subject_relation,omitempty" db:"subject_relation"`
	Metadata        map[string]any `json:"metadata,omitempty" db:"metadata"`
	CreatedAt       time.Time      `json:"created_at" db:"created_at"`
}

// ListFilter contains filters for listing relation tuples.
type ListFilter struct {
	TenantID        string  `json:"tenant_id,omitempty"`
	NamespacePath   *string `json:"namespace_path,omitempty"`
	NamespacePrefix string  `json:"namespace_prefix,omitempty"`
	ObjectType      string  `json:"object_type,omitempty"`
	ObjectID        string  `json:"object_id,omitempty"`
	Relation        string  `json:"relation,omitempty"`
	SubjectType     string  `json:"subject_type,omitempty"`
	SubjectID       string  `json:"subject_id,omitempty"`
	SubjectRelation string  `json:"subject_relation,omitempty"`
	Limit           int     `json:"limit,omitempty"`
	Offset          int     `json:"offset,omitempty"`
}
