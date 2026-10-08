// members.go: the member-cap guards.
//
// READ THIS BEFORE REMOVING THEM AS REDUNDANT. No store enforces
// Role.MaxMembers: none counts a role's members before inserting an
// assignment, and none compares a new cap with the members a role already
// has. warden defines ErrMaxMembersExceeded, and nothing returns it.
//
// The cap is enforced above the store, in package assignment, and every
// warden write path calls it. Assigning a subject goes through
// assignment.CheckMemberCap here (guardMemberCap) and in the REST
// assignment create. Lowering a cap goes through
// assignment.CheckCapLowering here (guardCapLowering), in the REST role
// update and in a DSL apply. The one deliberate exception is
// BootstrapAdmin (extension/bootstrap.go), the break-glass path that
// assigns the bootstrap admin role whatever its cap says, so a capped
// bootstrap role can end up over its cap. Code that writes through the
// store directly checks nothing.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
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
	return mapWardenError(assignment.CheckMemberCap(ctx, s, tenantID, r.ID, r.Name, r.MaxMembers, subjectKind, subjectID, now))
}

// guardCapLowering refuses a role update that lowers the member cap below
// the role's live member count. before is the role as stored; newCap is the
// cap the update would write. The count is assignment.LiveMembers, the same
// one guardMemberCap counts against, so when this checks a lowered cap it
// counts exactly the members the assignment guard would.
//
// The count read and the update's write are not atomic: an assignment made
// in between can leave the role over its new cap. See
// assignment.CheckCapLowering.
func guardCapLowering(ctx context.Context, s store.Store, tenantID string, before *role.Role, newCap int, now time.Time) error {
	return mapWardenError(assignment.CheckCapLowering(ctx, s, tenantID, before.ID, before.Name, before.MaxMembers, newCap, now))
}

// isLive reports whether an assignment grants anything at instant now. It
// is assignment.IsLive, the definition of "expired" the whole assignment
// surface uses.
func isLive(a *assignment.Assignment, now time.Time) bool {
	return assignment.IsLive(a, now)
}
