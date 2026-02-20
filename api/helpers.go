package api

import (
	"errors"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// mapError maps domain errors to Forge HTTP errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if isNotFound(err) {
		return forge.NotFound(err.Error())
	}
	if errors.Is(err, warden.ErrSystemRoleImmutable) || errors.Is(err, warden.ErrSystemPermissionImmutable) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrDuplicateAssignment) || errors.Is(err, warden.ErrDuplicateRelation) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrCyclicRoleInheritance) || errors.Is(err, warden.ErrMaxMembersExceeded) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrInvalidCondition) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrAccessDenied) {
		return forge.Forbidden(err.Error())
	}
	return err
}

func isNotFound(err error) bool {
	return errors.Is(err, warden.ErrRoleNotFound) ||
		errors.Is(err, warden.ErrPermissionNotFound) ||
		errors.Is(err, warden.ErrAssignmentNotFound) ||
		errors.Is(err, warden.ErrPolicyNotFound) ||
		errors.Is(err, warden.ErrRelationNotFound) ||
		errors.Is(err, warden.ErrResourceTypeNotFound)
}

func defaultLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}
