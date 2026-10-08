// immutable.go: the system-entity guard.
//
// READ THIS BEFORE REMOVING IT AS REDUNDANT. It is not redundant. No store
// checks IsSystem on update or delete, and the engine does not check it.
// The rule lives in role.CheckWritable and permission.CheckWritable, which
// this file and the REST API (api/role_handler.go, api/permission_handler.go)
// both call, so the two refuse the same writes in the same words. Without
// these two functions this dashboard will let an operator rename a system
// role, change its parent, or delete it, and the store will do it.
//
// The guard belongs here rather than in each handler so that the plans
// after this one cannot add a role or permission write that forgets it.
//
// schema.plan and schema.apply write through dsl.Apply, which cannot call
// these two. They set dsl.ApplyOptions.ProtectSystem instead, which refuses
// the same writes with the same sentence, as a diagnostic at the
// declaration. That sentence names a role by its slug, which is what the
// source declares, where this guard and REST name it by its name.
package contract

import (
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// guardError carries a refusal that is, at once, a warden sentinel a caller
// can check with errors.Is and a dashboard wire error a caller can pull out
// with errors.As.
//
// dashcontract.Error has no field to wrap a cause and no Unwrap method: its
// own Is method only matches other *dashcontract.Error values by Code, so
// returning a bare *dashcontract.Error here would lose errors.Is against
// warden.ErrSystemRoleImmutable. Go's multi-error Unwrap (Unwrap() []error)
// lets one value stand in the chain for both: errors.Is finds the sentinel
// through the cause branch, and errors.As finds *dashcontract.Error through
// the wire branch, which is also how the dispatcher recovers the wire shape
// (extensions/dashboard/contract/dispatcher/dispatcher.go maps errors with
// errors.As(err, &ce) where ce is *contract.Error).
type guardError struct {
	wire  *dashcontract.Error
	cause error
}

func (e *guardError) Error() string   { return e.wire.Error() }
func (e *guardError) Unwrap() []error { return []error{e.wire, e.cause} }

// guardSystemRole refuses a write to a system role, with
// role.CheckWritable's refusal.
//
// It is a permission fact, not bad input: retyping the request will not
// make a system role writable, so the wire code is PERMISSION_DENIED rather
// than BAD_REQUEST.
func guardSystemRole(r *role.Role) error {
	return asGuardError(role.CheckWritable(r))
}

// guardSystemPermission refuses a write to a system permission, with
// permission.CheckWritable's refusal.
func guardSystemPermission(p *permission.Permission) error {
	return asGuardError(permission.CheckWritable(p))
}

// asGuardError gives a shared refusal its PERMISSION_DENIED wire shape and
// keeps it in the chain, so errors.Is still finds the warden sentinel it
// wraps. A nil refusal stays nil.
func asGuardError(refusal error) error {
	if refusal == nil {
		return nil
	}
	return &guardError{
		wire: &dashcontract.Error{
			Code:    dashcontract.CodePermissionDenied,
			Message: refusal.Error(),
		},
		cause: refusal,
	}
}
