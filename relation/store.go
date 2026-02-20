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
	DeleteRelationTuple(ctx context.Context, tenantID, objectType, objectID, relation, subjectType, subjectID string) error

	// ListRelations returns relation tuples matching the filter.
	ListRelations(ctx context.Context, filter *ListFilter) ([]*Tuple, error)

	// CountRelations returns the number of tuples matching the filter.
	CountRelations(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRelationSubjects returns tuples where the given object has the specified relation.
	ListRelationSubjects(ctx context.Context, tenantID, objectType, objectID, relation string) ([]*Tuple, error)

	// ListRelationObjects returns tuples where the given subject has the specified relation.
	ListRelationObjects(ctx context.Context, tenantID, subjectType, subjectID, relation string) ([]*Tuple, error)

	// CheckDirectRelation checks if a direct relation exists between subject and object.
	CheckDirectRelation(ctx context.Context, tenantID, objectType, objectID, relation, subjectType, subjectID string) (bool, error)

	// DeleteRelationsByObject removes all relation tuples for an object.
	DeleteRelationsByObject(ctx context.Context, tenantID, objectType, objectID string) error

	// DeleteRelationsBySubject removes all relation tuples for a subject.
	DeleteRelationsBySubject(ctx context.Context, tenantID, subjectType, subjectID string) error

	// DeleteRelationsByTenant removes all relation tuples for a tenant.
	DeleteRelationsByTenant(ctx context.Context, tenantID string) error
}
