package warden

import "errors"

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

	// ErrDuplicateAssignment is returned when a role is already assigned to a subject.
	ErrDuplicateAssignment = errors.New("warden: role already assigned to subject")

	// ErrDuplicateRelation is returned when a relation tuple already exists.
	ErrDuplicateRelation = errors.New("warden: relation tuple already exists")

	// ErrCyclicRoleInheritance is returned when role inheritance would create a cycle.
	ErrCyclicRoleInheritance = errors.New("warden: cyclic role inheritance detected")

	// ErrMaxMembersExceeded is returned when a role's member limit is reached.
	ErrMaxMembersExceeded = errors.New("warden: role max members exceeded")

	// ErrInvalidCondition is returned when a policy condition is malformed.
	ErrInvalidCondition = errors.New("warden: invalid policy condition")

	// ErrGraphDepthExceeded is returned when the relation graph walk exceeds max depth.
	ErrGraphDepthExceeded = errors.New("warden: relation graph depth exceeded")
)
