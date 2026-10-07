package assignment

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/warden/id"
)

// Member is one subject holding a role: a distinct (subject kind, subject
// id). Assignment uniqueness includes namespace, resource type and resource
// id, so one subject can hold several rows for one role and still be one
// member.
type Member struct {
	Kind string
	ID   string
}

// IsLive reports whether a grants anything at instant now.
//
// This is the same test the engine applies when resolving roles
// (store/memory/store.go's ListRolesForSubject), and it is the definition
// of "expired" the whole assignment surface uses. A nil ExpiresAt never
// expires.
func IsLive(a *Assignment, now time.Time) bool {
	return a.ExpiresAt == nil || a.ExpiresAt.After(now)
}

// LiveMembers returns the distinct subjects among held that hold a live
// assignment at now. It is the one definition of a role's members that the
// member cap is checked against, both when a subject is assigned and when
// the cap is changed, so the two checks cannot disagree about who counts.
func LiveMembers(held []*Assignment, now time.Time) map[Member]struct{} {
	members := make(map[Member]struct{}, len(held))
	for _, a := range held {
		if IsLive(a, now) {
			members[Member{Kind: a.SubjectKind, ID: a.SubjectID}] = struct{}{}
		}
	}
	return members
}

// SubjectsForRoleLister is the one store read the cap checks need.
type SubjectsForRoleLister interface {
	ListSubjectsForRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*Assignment, error)
}

// CapBelowMembersError refuses a member cap lower than the number of live
// members the role already has. Every write path returns this same text:
// the dashboard contract as CONFLICT, REST as 409, and a DSL apply as the
// error that stops it.
type CapBelowMembersError struct {
	RoleName string
	Members  int
	Cap      int
}

func (e *CapBelowMembersError) Error() string {
	return fmt.Sprintf("%q has %d members, so its cap cannot be lowered to %d", e.RoleName, e.Members, e.Cap)
}

// CheckCapLowering refuses changing a role's member cap from oldCap to
// newCap when newCap is a positive number below the role's live member
// count (LiveMembers at now). It returns a *CapBelowMembersError for the
// refusal, or the store's error if the read fails.
//
// It reads nothing and refuses nothing unless the cap is being lowered: a
// cap of 0 or below means unlimited, so clearing it, raising it, keeping it
// unchanged, or moving between unlimited values always passes. A role can
// already be over its cap (the REST assignment write does not check it, a
// cap could be lowered under its members before this check existed, and
// the dashboard's assignment check is not atomic), and keeping that cap
// unchanged never blocks an edit to the role's other fields. Moving from
// unlimited to a positive cap is a lowering and is checked.
//
// The count read and the caller's write are NOT atomic. No store offers a
// conditional role update tied to the assignment count, so an assignment
// created between this read and the write can leave the role over its new
// cap. Like the assignment-side cap check, this is best effort under
// concurrency, not a guarantee.
func CheckCapLowering(ctx context.Context, s SubjectsForRoleLister, tenantID string, roleID id.RoleID, roleName string, oldCap, newCap int, now time.Time) error {
	if newCap <= 0 || (oldCap > 0 && newCap >= oldCap) {
		return nil
	}
	held, err := s.ListSubjectsForRole(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	n := len(LiveMembers(held, now))
	if n <= newCap {
		return nil
	}
	return &CapBelowMembersError{RoleName: roleName, Members: n, Cap: newCap}
}
