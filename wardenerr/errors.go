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
