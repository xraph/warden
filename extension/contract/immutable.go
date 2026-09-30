// immutable.go: the system-entity guard.
//
// READ THIS BEFORE REMOVING IT AS REDUNDANT. It is not redundant. Warden
// defines ErrSystemRoleImmutable and ErrSystemPermissionImmutable in
// errors.go, and a repository-wide grep finds ZERO places that return
// either one. No store checks IsSystem on update or delete. The HTTP API
// does not check it. The engine does not check it.
//
// So IsSystem is, everywhere below this file, a display flag with no teeth.
// Without these two functions this dashboard will let an operator rename a
// system role, change its parent, or delete it, and the store will do it.
//
// The guard belongs here rather than in each handler so that the plans
// after this one cannot add a role or permission write that forgets it.
//
// schema.plan and schema.apply write through dsl.Apply, which cannot call
// these two. They set dsl.ApplyOptions.ProtectSystem instead, which refuses
// the same writes in the same words, as a diagnostic at the declaration.
package contract

import (
	"fmt"

	"github.com/xraph/warden"
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

// guardSystemRole refuses a write to a system role.
//
// It is a permission fact, not bad input: retyping the request will not
// make a system role writable, so the wire code is PERMISSION_DENIED rather
// than BAD_REQUEST.
func guardSystemRole(r *role.Role) error {
	if r == nil || !r.IsSystem {
		return nil
	}
	return &guardError{
		wire: &dashcontract.Error{
			Code: dashcontract.CodePermissionDenied,
			Message: fmt.Sprintf("%q is a system role and cannot be changed or deleted",
				r.Name),
		},
		cause: warden.ErrSystemRoleImmutable,
	}
}

// guardSystemPermission refuses a write to a system permission.
func guardSystemPermission(p *permission.Permission) error {
	if p == nil || !p.IsSystem {
		return nil
	}
	return &guardError{
		wire: &dashcontract.Error{
			Code: dashcontract.CodePermissionDenied,
			Message: fmt.Sprintf("%q is a system permission and cannot be changed or deleted",
				p.Name),
		},
		cause: warden.ErrSystemPermissionImmutable,
	}
}
