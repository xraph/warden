package warden

import (
	"errors"

	"github.com/xraph/warden/wardenerr"
)

var (
	// ErrAccessDenied is returned when an authorization check fails.
	ErrAccessDenied = errors.New("warden: access denied")

	// ErrNotFound is the common base error for the missing-entity errors
	// below. Use errors.Is(err, ErrNotFound) to match any of them.
	//
	// Defined in wardenerr so that low-level subpackages (e.g. store/memory)
	// can return typed not-found errors without an import cycle.
	ErrNotFound = wardenerr.ErrNotFound

	// ErrRoleNotFound is returned when a role cannot be found in the tenant.
	// Every store returns this for a by-ID lookup whose tenant does not own
	// the row, so a caller cannot distinguish "no such role" from "that role
	// belongs to someone else".
	ErrRoleNotFound = wardenerr.ErrRoleNotFound

	// ErrPermissionNotFound is returned when a permission cannot be found in the tenant.
	ErrPermissionNotFound = wardenerr.ErrPermissionNotFound

	// ErrAssignmentNotFound is returned when an assignment cannot be found in the tenant.
	ErrAssignmentNotFound = wardenerr.ErrAssignmentNotFound

	// ErrPolicyNotFound is returned when a policy cannot be found in the tenant.
	ErrPolicyNotFound = wardenerr.ErrPolicyNotFound

	// ErrStaleWrite is the common base error for a conditional write that
	// found the record changed since the caller read it. Use
	// errors.Is(err, ErrStaleWrite) to match any of the specialized
	// conflict errors, such as ErrPolicyVersionConflict.
	ErrStaleWrite = wardenerr.ErrStaleWrite

	// ErrPolicyVersionConflict is returned by UpdatePolicyIfVersion when the
	// stored policy's version is not the one the caller expected. Nothing is
	// written. Wraps ErrStaleWrite.
	ErrPolicyVersionConflict = wardenerr.ErrPolicyVersionConflict

	// ErrRelationNotFound is returned when a relation tuple cannot be found in the tenant.
	ErrRelationNotFound = wardenerr.ErrRelationNotFound

	// ErrResourceTypeNotFound is returned when a resource type cannot be found in the tenant.
	ErrResourceTypeNotFound = wardenerr.ErrResourceTypeNotFound

	// ErrCheckLogNotFound is returned when a check log entry cannot be found in the tenant.
	ErrCheckLogNotFound = wardenerr.ErrCheckLogNotFound

	// ErrSystemRoleImmutable is returned when trying to modify a system role.
	ErrSystemRoleImmutable = errors.New("warden: system role cannot be modified")

	// ErrSystemPermissionImmutable is returned when trying to modify a system permission.
	ErrSystemPermissionImmutable = errors.New("warden: system permission cannot be modified")

	// ErrAlreadyExists is the common base error for entity-uniqueness
	// violations. Use errors.Is(err, ErrAlreadyExists) to match any of the
	// specialized ErrDuplicate* errors below.
	//
	// Defined in wardenerr so that low-level subpackages (e.g. store/memory)
	// can return typed duplicate errors without an import cycle.
	ErrAlreadyExists = wardenerr.ErrAlreadyExists

	// ErrDuplicateRole is returned when a role would violate the
	// (tenant_id, namespace_path, slug) uniqueness constraint.
	ErrDuplicateRole = wardenerr.ErrDuplicateRole

	// ErrDuplicatePermission is returned when a permission would violate the
	// (tenant_id, namespace_path, name) uniqueness constraint.
	ErrDuplicatePermission = wardenerr.ErrDuplicatePermission

	// ErrDuplicatePolicy is returned when a policy would violate the
	// (tenant_id, namespace_path, name) uniqueness constraint.
	ErrDuplicatePolicy = wardenerr.ErrDuplicatePolicy

	// ErrDuplicateResourceType is returned when a resource type would violate
	// the (tenant_id, namespace_path, name) uniqueness constraint.
	ErrDuplicateResourceType = wardenerr.ErrDuplicateResourceType

	// ErrDuplicateAssignment is returned when a role is already assigned to a
	// subject within the same scope. Wraps ErrAlreadyExists.
	ErrDuplicateAssignment = wardenerr.ErrDuplicateAssignment

	// ErrDuplicateRelation is returned when a relation tuple already exists.
	// Wraps ErrAlreadyExists.
	ErrDuplicateRelation = wardenerr.ErrDuplicateRelation

	// ErrCyclicRoleInheritance is returned when role inheritance would create a cycle.
	ErrCyclicRoleInheritance = errors.New("warden: cyclic role inheritance detected")

	// ErrMaxMembersExceeded is returned when a role's member limit is reached.
	ErrMaxMembersExceeded = errors.New("warden: role max members exceeded")

	// ErrInvalidCondition is returned when a policy condition is malformed.
	ErrInvalidCondition = errors.New("warden: invalid policy condition")

	// ErrGraphDepthExceeded is returned when the relation graph walk exceeds max depth.
	ErrGraphDepthExceeded = errors.New("warden: relation graph depth exceeded")

	// ErrTenantRequired is returned by Check when the resolved scope has no
	// tenant ID and Config.RequireTenant is true (the default), and by
	// RunTenantMaintenance when it is given no tenant.
	ErrTenantRequired = wardenerr.ErrTenantRequired

	// ErrGraphBudgetExceeded is returned when a ReBAC graph traversal
	// exceeds its configured visited-node or fan-out budget.
	ErrGraphBudgetExceeded = errors.New("warden: graph traversal budget exceeded")

	// ErrUnauthenticated is returned when a check cannot proceed because no
	// subject/actor identity is available.
	ErrUnauthenticated = errors.New("warden: unauthenticated")
)
