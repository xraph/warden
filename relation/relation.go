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
// NamespacePath places the tuple in the namespace tree. Tuples cascade the
// same way roles and policies do: a tuple at namespace N is in scope for a
// check at N and at every namespace below N, because the engine hands
// AncestorNamespaces(checkNamespace) to every tuple lookup a check makes
// (the direct check, the expression evaluator and the graph walker). A
// tuple at N is never matched by a check at an ancestor of N or at a
// sibling. ListFilter's NamespacePath is different: it is an exact match,
// so listing N does not return the ancestors' tuples that also apply at N.
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
	CreatedBy       string         `json:"created_by,omitempty" db:"created_by"`
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
