package relation

import (
	"context"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for relation tuples (ReBAC).
type Store interface {
	// CreateRelation persists a new relation tuple.
	CreateRelation(ctx context.Context, t *Tuple) error

	// DeleteRelation removes a relation tuple by ID.
	DeleteRelation(ctx context.Context, relID id.RelationID) error

	// DeleteRelationTuple removes a specific relation tuple by its composite key.
	DeleteRelationTuple(ctx context.Context, tenantID, namespacePath, objectType, objectID, relation, subjectType, subjectID string) error

	// ListRelations returns relation tuples matching the filter.
	ListRelations(ctx context.Context, filter *ListFilter) ([]*Tuple, error)

	// CountRelations returns the number of tuples matching the filter.
	CountRelations(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRelationSubjects returns tuples where the given object has the
	// specified relation in any of the given namespace paths. Pass the
	// request namespace and its ancestors (see warden.AncestorNamespaces) to
	// honor namespace inheritance, or a single-element slice for an exact
	// lookup. An empty slice matches any namespace.
	ListRelationSubjects(ctx context.Context, tenantID string, namespacePaths []string, objectType, objectID, relation string) ([]*Tuple, error)

	// ListRelationObjects returns tuples where the given subject has the
	// specified relation in the given namespace.
	ListRelationObjects(ctx context.Context, tenantID, namespacePath, subjectType, subjectID, relation string) ([]*Tuple, error)

	// CheckDirectRelation reports whether a direct relation exists between
	// subject and object in any of the given namespace paths. Pass the request
	// namespace and its ancestors to honor namespace inheritance, or a
	// single-element slice for an exact lookup. An empty slice matches any
	// namespace.
	CheckDirectRelation(ctx context.Context, tenantID string, namespacePaths []string, objectType, objectID, relation, subjectType, subjectID string) (bool, error)

	// DeleteRelationsByObject removes all relation tuples for an object.
	DeleteRelationsByObject(ctx context.Context, tenantID, objectType, objectID string) error

	// DeleteRelationsBySubject removes all relation tuples for a subject.
	DeleteRelationsBySubject(ctx context.Context, tenantID, subjectType, subjectID string) error

	// DeleteRelationsByTenant removes all relation tuples for a tenant.
	DeleteRelationsByTenant(ctx context.Context, tenantID string) error
}
