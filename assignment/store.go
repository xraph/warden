package assignment

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for role assignments.
type Store interface {
	// CreateAssignment persists a new assignment.
	CreateAssignment(ctx context.Context, a *Assignment) error

	// GetAssignment retrieves an assignment by ID.
	GetAssignment(ctx context.Context, assID id.AssignmentID) (*Assignment, error)

	// DeleteAssignment removes an assignment by ID.
	DeleteAssignment(ctx context.Context, assID id.AssignmentID) error

	// ListAssignments returns assignments matching the filter.
	ListAssignments(ctx context.Context, filter *ListFilter) ([]*Assignment, error)

	// CountAssignments returns the number of assignments matching the filter.
	CountAssignments(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRolesForSubject returns role IDs assigned to a subject (global).
	ListRolesForSubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]id.RoleID, error)

	// ListRolesForSubjectOnResource returns role IDs assigned to a subject
	// scoped to a specific resource.
	ListRolesForSubjectOnResource(ctx context.Context, tenantID, subjectKind, subjectID, resourceType, resourceID string) ([]id.RoleID, error)

	// ListSubjectsForRole returns all assignments for a given role.
	ListSubjectsForRole(ctx context.Context, roleID id.RoleID) ([]*Assignment, error)

	// DeleteExpiredAssignments removes assignments that have expired before the given time.
	DeleteExpiredAssignments(ctx context.Context, now time.Time) (int64, error)

	// DeleteAssignmentsBySubject removes all assignments for a subject.
	DeleteAssignmentsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) error

	// DeleteAssignmentsByRole removes all assignments for a role.
	DeleteAssignmentsByRole(ctx context.Context, roleID id.RoleID) error

	// DeleteAssignmentsByTenant removes all assignments for a tenant.
	DeleteAssignmentsByTenant(ctx context.Context, tenantID string) error
}
