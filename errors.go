package warden

import (
	"errors"

	"github.com/xraph/warden/wardenerr"
)

var (
	// ErrAccessDenied is returned when an authorization check fails.
	ErrAccessDenied = errors.New("warden: access denied")

	// ErrRoleNotFound is returned when a role cannot be found.
	ErrRoleNotFound = errors.New("warden: role not found")

	// ErrPermissionNotFound is returned when a permission cannot be found.
	ErrPermissionNotFound = errors.New("warden: permission not found")

	// ErrAssignmentNotFound is returned when an assignment cannot be found.
	ErrAssignmentNotFound = errors.New("warden: assignment not found")

	// ErrPolicyNotFound is returned when a policy cannot be found.
	ErrPolicyNotFound = errors.New("warden: policy not found")

	// ErrRelationNotFound is returned when a relation tuple cannot be found.
	ErrRelationNotFound = errors.New("warden: relation not found")

	// ErrResourceTypeNotFound is returned when a resource type cannot be found.
	ErrResourceTypeNotFound = errors.New("warden: resource type not found")

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
)
