package assignment

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for role assignments.
//
// Every by-ID operation takes the tenant as a mandatory parameter and
// filters on it alongside the primary key. A call whose tenant does not own
// the row returns ErrAssignmentNotFound and changes nothing.
type Store interface {
	// CreateAssignment persists a new assignment.
	CreateAssignment(ctx context.Context, a *Assignment) error

	// GetAssignment retrieves an assignment by ID within a tenant.
	GetAssignment(ctx context.Context, tenantID string, assID id.AssignmentID) (*Assignment, error)

	// DeleteAssignment removes an assignment by ID within a tenant.
	DeleteAssignment(ctx context.Context, tenantID string, assID id.AssignmentID) error

	// ListAssignments returns assignments matching the filter.
	ListAssignments(ctx context.Context, filter *ListFilter) ([]*Assignment, error)

	// CountAssignments returns the number of assignments matching the filter.
	CountAssignments(ctx context.Context, filter *ListFilter) (int64, error)

	// ListRolesForSubject returns role IDs assigned to a subject (global)
	// across the given namespace paths. Pass nil or an empty slice to match
	// any namespace (legacy/unscoped behavior).
	//
	// An assignment whose ExpiresAt has passed is excluded, as if the row
	// did not exist: the backend applies `expires_at IS NULL OR
	// expires_at > now` in the same query, so an expired grant can never
	// leak into a Check() decision between expiring and a cleanup sweep
	// (DeleteExpiredAssignments) getting around to deleting it.
	ListRolesForSubject(ctx context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID string) ([]id.RoleID, error)

	// ListRolesForSubjectOnResource returns role IDs assigned to a subject
	// scoped to a specific resource, across the given namespace paths.
	//
	// Expired assignments are excluded the same way as ListRolesForSubject.
	ListRolesForSubjectOnResource(ctx context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID, resourceType, resourceID string) ([]id.RoleID, error)

	// ListSubjectsForRole returns all assignments for a given role within a
	// tenant.
	ListSubjectsForRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*Assignment, error)

	// ListExpiringAssignments returns the tenant's assignments that expire
	// before the given time, oldest expiry first. Used by access reviews.
	// A limit of 0 means the backend default of 1000.
	ListExpiringAssignments(ctx context.Context, tenantID string, before time.Time, limit int) ([]*Assignment, error)

	// DeleteExpiredAssignments removes assignments that have expired before
	// the given time, in every tenant.
	DeleteExpiredAssignments(ctx context.Context, now time.Time) (int64, error)

	// DeleteExpiredAssignmentsForTenant removes one tenant's assignments that
	// have expired before the given time and reports how many rows it
	// removed. No other tenant's rows are touched. An empty tenantID returns
	// wardenerr.ErrTenantRequired and deletes nothing; it never means every
	// tenant.
	DeleteExpiredAssignmentsForTenant(ctx context.Context, tenantID string, now time.Time) (int64, error)

	// DeleteAssignmentsBySubject removes all assignments for a subject.
	DeleteAssignmentsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) error

	// DeleteAssignmentsByRole removes a tenant's assignments for a role.
	DeleteAssignmentsByRole(ctx context.Context, tenantID string, roleID id.RoleID) error

	// DeleteAssignmentsByTenant removes all assignments for a tenant.
	DeleteAssignmentsByTenant(ctx context.Context, tenantID string) error
}
