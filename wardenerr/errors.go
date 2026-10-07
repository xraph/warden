// Package wardenerr holds shared sentinel errors used across warden
// subpackages. It exists as a leaf package so that low-level packages
// (e.g. store/memory) can return typed errors without importing the
// root warden package, which would create an import cycle in tests.
//
// The root warden package re-exports these as aliases (warden.ErrXX),
// so callers should prefer the warden.* names. Subpackages that
// implement store interfaces import wardenerr directly.
package wardenerr

import (
	"errors"
	"fmt"
)

// ErrAlreadyExists is the common base error for entity-uniqueness
// violations. Use errors.Is(err, ErrAlreadyExists) to match any of the
// specialized ErrDuplicate* errors below.
var ErrAlreadyExists = errors.New("warden: already exists")

// ErrDuplicateRole is returned when a role would violate the
// (tenant_id, namespace_path, slug) uniqueness constraint.
var ErrDuplicateRole = fmt.Errorf("warden: role already exists in this scope: %w", ErrAlreadyExists)

// ErrDuplicatePermission is returned when a permission would violate the
// (tenant_id, namespace_path, name) uniqueness constraint.
var ErrDuplicatePermission = fmt.Errorf("warden: permission already exists in this scope: %w", ErrAlreadyExists)

// ErrDuplicatePolicy is returned when a policy would violate the
// (tenant_id, namespace_path, name) uniqueness constraint.
var ErrDuplicatePolicy = fmt.Errorf("warden: policy already exists in this scope: %w", ErrAlreadyExists)

// ErrDuplicateResourceType is returned when a resource type would violate
// the (tenant_id, namespace_path, name) uniqueness constraint.
var ErrDuplicateResourceType = fmt.Errorf("warden: resource type already exists in this scope: %w", ErrAlreadyExists)

// ErrDuplicateAssignment is returned when a role is already assigned to a
// subject within the same scope. Wraps ErrAlreadyExists.
var ErrDuplicateAssignment = fmt.Errorf("warden: role already assigned to subject: %w", ErrAlreadyExists)

// ErrDuplicateRelation is returned when a relation tuple already exists.
// Wraps ErrAlreadyExists.
var ErrDuplicateRelation = fmt.Errorf("warden: relation tuple already exists: %w", ErrAlreadyExists)

// ErrNotFound is the common base for the missing-entity errors below. A
// by-ID lookup that carries the wrong tenant returns the same sentinel a
// genuinely missing row returns: a distinct "forbidden" error would confirm
// that the ID exists in some other tenant.
var ErrNotFound = errors.New("warden: not found")

// ErrRoleNotFound is returned when a role cannot be found in the tenant.
var ErrRoleNotFound = fmt.Errorf("warden: role not found: %w", ErrNotFound)

// ErrPermissionNotFound is returned when a permission cannot be found in the tenant.
var ErrPermissionNotFound = fmt.Errorf("warden: permission not found: %w", ErrNotFound)

// ErrAssignmentNotFound is returned when an assignment cannot be found in the tenant.
var ErrAssignmentNotFound = fmt.Errorf("warden: assignment not found: %w", ErrNotFound)

// ErrPolicyNotFound is returned when a policy cannot be found in the tenant.
var ErrPolicyNotFound = fmt.Errorf("warden: policy not found: %w", ErrNotFound)

// ErrRelationNotFound is returned when a relation tuple cannot be found in the tenant.
var ErrRelationNotFound = fmt.Errorf("warden: relation not found: %w", ErrNotFound)

// ErrResourceTypeNotFound is returned when a resource type cannot be found in the tenant.
var ErrResourceTypeNotFound = fmt.Errorf("warden: resource type not found: %w", ErrNotFound)

// ErrCheckLogNotFound is returned when a check log entry cannot be found in the tenant.
var ErrCheckLogNotFound = fmt.Errorf("warden: check log not found: %w", ErrNotFound)

// ErrStaleWrite is returned when a conditional write finds the record changed
// since the caller read it.
var ErrStaleWrite = errors.New("warden: changed since it was read")

// ErrPolicyVersionConflict is returned by UpdatePolicyIfVersion when the
// stored policy's version is not the one the caller expected.
var ErrPolicyVersionConflict = fmt.Errorf("warden: policy changed since it was read: %w", ErrStaleWrite)

// ErrTenantRequired is returned when an operation needs a tenant ID and was
// given none. Check returns it when the resolved scope has no tenant and
// Config.RequireTenant is true; the tenant-scoped maintenance purges return
// it for an empty tenant rather than treating empty as every tenant.
var ErrTenantRequired = errors.New("warden: tenant is required")

// ErrSystemRoleImmutable is returned when a write would change or delete a
// system role.
var ErrSystemRoleImmutable = errors.New("warden: system role cannot be modified")

// ErrSystemPermissionImmutable is returned when a write would change or
// delete a system permission.
var ErrSystemPermissionImmutable = errors.New("warden: system permission cannot be modified")

// ErrCyclicRoleInheritance is returned when a role's parent would make the
// role its own ancestor.
var ErrCyclicRoleInheritance = errors.New("warden: cyclic role inheritance detected")
