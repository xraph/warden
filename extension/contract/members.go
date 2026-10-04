// members.go: the member-cap guard.
//
// READ THIS BEFORE REMOVING IT AS REDUNDANT. Role.MaxMembers is enforced
// nowhere below this file. warden defines ErrMaxMembersExceeded, and a
// repository-wide grep finds it HANDLED once (api/helpers.go maps it to a
// status) and RETURNED zero times. No store counts a role's members before
// inserting an assignment.
//
// So MaxMembers is, everywhere below the contract layer, a number somebody
// typed into a form. A role capped at five accepts five hundred assignments
// and nothing complains. This is the same shape as IsSystem before
// immutable.go, and the same reasoning applies: the contract is the only
// enforcement point that exists.
package contract

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// guardMemberCap refuses an assignment that would take a role past its cap.
//
// Three rules that are easy to get backwards:
//
// MaxMembers 0 means UNLIMITED. There is no field comment saying so, so the
// evidence is the `omitempty` tag on role.Role.MaxMembers and the deleted
// templ dashboard's own guard, which rendered the cap only
// `if r.MaxMembers > 0` (MIGRATION.md, Role detail, "Max Members (when
// above 0)"; read the source with
// `git show 45701f8:dashboard/pages/role_detail_templ.go`, line 328). A
// guard that read 0 as "no members" would block every assignment on every
// role that never set a cap, which is most of them.
//
// Only LIVE members occupy a seat. An expired assignment grants nothing
// (ListRolesForSubject filters it), so counting it would let old grants pile
// up until a role could never be assigned again.
//
// A member is a distinct (subject kind, subject id), not a row. Assignment
// uniqueness includes namespace, resource type and resource id, so one
// subject can hold several rows for one role. Counting rows would let one
// person fill a role capped at two, and would refuse a third binding for a
// subject who is already a member and so adds nobody. A subject who already
// holds the role live is therefore never refused.
//
// This is check-then-insert and it is NOT atomic. No store offers a
// conditional insert, so two concurrent creates can both pass the check and
// take a role one past its cap. The cap is best-effort under concurrency,
// not a guarantee; do not build anything that relies on it being exact.
func guardMemberCap(ctx context.Context, s store.Store, tenantID string, r *role.Role, subjectKind, subjectID string, now time.Time) error {
	if r.MaxMembers <= 0 {
		return nil
	}
	held, err := s.ListSubjectsForRole(ctx, tenantID, r.ID)
	if err != nil {
		return mapWardenError(err)
	}
	type member struct{ kind, id string }
	members := map[member]struct{}{}
	for _, a := range held {
		if isLive(a, now) {
			members[member{a.SubjectKind, a.SubjectID}] = struct{}{}
		}
	}
	if _, already := members[member{subjectKind, subjectID}]; already {
		return nil
	}
	if len(members) < r.MaxMembers {
		return nil
	}
	return &dashcontract.Error{
		Code: dashcontract.CodeConflict,
		Message: fmt.Sprintf("%q is capped at %d members and already has %d",
			r.Name, r.MaxMembers, len(members)),
	}
}

// isLive reports whether an assignment grants anything at instant now.
//
// This is the same test the engine applies when resolving roles
// (store/memory/store.go's ListRolesForSubject), and it is the definition of
// "expired" the whole assignment surface uses. A nil ExpiresAt never
// expires.
func isLive(a *assignment.Assignment, now time.Time) bool {
	return a.ExpiresAt == nil || a.ExpiresAt.After(now)
}
