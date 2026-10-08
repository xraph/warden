package contract

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// cappedRoleWithMembers stores a role named "Small" with the given cap and
// binds one live user per name in live and one expired user per name in
// expired.
func cappedRoleWithMembers(t *testing.T, s *memory.Store, maxMembers int, live, expired []string) *role.Role {
	t.Helper()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: maxMembers}
	if err := s.CreateRole(context.Background(), r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	for _, who := range live {
		seedAssignment(t, s, r.ID.String(), who, nil)
	}
	past := time.Now().Add(-time.Hour)
	for _, who := range expired {
		seedAssignment(t, s, r.ID.String(), who, &past)
	}
	return r
}

func storedRole(t *testing.T, s *memory.Store, r *role.Role) *role.Role {
	t.Helper()
	got, err := s.GetRole(context.Background(), "t1", r.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	return got
}

func TestRolesUpdateRefusesACapBelowTheLiveMemberCount(t *testing.T) {
	// The assignment guard only stops a role growing past its cap. Without
	// this one, lowering the cap under the members already holding the role
	// stores a cap the role is already over.
	s := memory.New()
	r := cappedRoleWithMembers(t, s, 5, []string{"a", "b", "c"}, nil)
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	two, newName := 2, "Renamed"
	_, err := h(context.Background(), RoleUpdateInput{ID: r.ID.String(), MaxMembers: &two, Name: &newName}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("want CodeConflict, got %v", err)
	}
	if want := `"Small" has 3 members, so its cap cannot be lowered to 2`; ce.Message != want {
		t.Errorf("message = %q, want %q", ce.Message, want)
	}
	after := storedRole(t, s, r)
	if after.MaxMembers != 5 || after.Name != "Small" {
		t.Errorf("the refusal wrote something: cap %d, name %q", after.MaxMembers, after.Name)
	}
}

func TestRolesUpdateRefusesACapOnAnUncappedRoleBelowItsMembers(t *testing.T) {
	// 0 is unlimited, so setting any positive cap is a lowering.
	s := memory.New()
	r := cappedRoleWithMembers(t, s, 0, []string{"a", "b"}, nil)
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	one := 1
	_, err := h(context.Background(), RoleUpdateInput{ID: r.ID.String(), MaxMembers: &one}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("want CodeConflict, got %v", err)
	}
	if after := storedRole(t, s, r); after.MaxMembers != 0 {
		t.Errorf("cap = %d, want 0 (unchanged)", after.MaxMembers)
	}
}

func TestRolesUpdateSavesACapAtOrAboveTheLiveCountOrCleared(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newCap int
	}{
		{"exactly the live count", 3},
		{"raised", 10},
		{"cleared to unlimited", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			r := cappedRoleWithMembers(t, s, 5, []string{"a", "b", "c"}, nil)
			h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

			newCap := tc.newCap
			if _, err := h(context.Background(), RoleUpdateInput{ID: r.ID.String(), MaxMembers: &newCap}, principalFor("t1")); err != nil {
				t.Fatalf("roles.update: %v", err)
			}
			if after := storedRole(t, s, r); after.MaxMembers != tc.newCap {
				t.Errorf("cap = %d, want %d", after.MaxMembers, tc.newCap)
			}
		})
	}
}

func TestRolesUpdateDoesNotCountExpiredAssignmentsAgainstALoweredCap(t *testing.T) {
	// Two live and two expired: the role has two members. A cap of 2 fits,
	// and the refusal of 1 names 2, not 4.
	s := memory.New()
	r := cappedRoleWithMembers(t, s, 5, []string{"a", "b"}, []string{"old1", "old2"})
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	one, two := 1, 2
	_, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), MaxMembers: &one}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Message != `"Small" has 2 members, so its cap cannot be lowered to 1` {
		t.Fatalf("lowering to 1: want the refusal counting 2 live members, got %v", err)
	}
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), MaxMembers: &two}, principalFor("t1")); err != nil {
		t.Fatalf("lowering to the live count: %v", err)
	}
	if after := storedRole(t, s, r); after.MaxMembers != 2 {
		t.Errorf("cap = %d, want 2", after.MaxMembers)
	}
}

func TestRolesUpdateEditsAnOverFullRoleWhenTheCapIsUnchanged(t *testing.T) {
	// A role can already be over its cap: the assignment guard is not atomic,
	// and rows made before the cap was set are never revisited. The guard
	// fires only on a lowering, so the role's other fields stay editable,
	// with the cap omitted or resent as it is.
	s := memory.New()
	r := cappedRoleWithMembers(t, s, 1, []string{"a", "b", "c"}, nil)
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	first, second, same := "First", "Second", 1
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), Name: &first}, principalFor("t1")); err != nil {
		t.Fatalf("rename with the cap omitted: %v", err)
	}
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), Name: &second, MaxMembers: &same}, principalFor("t1")); err != nil {
		t.Fatalf("rename with the cap resent unchanged: %v", err)
	}
	if after := storedRole(t, s, r); after.Name != "Second" || after.MaxMembers != 1 {
		t.Errorf("stored name %q cap %d, want Second and 1", after.Name, after.MaxMembers)
	}
}

func TestCapLoweringAndTheAssignmentGuardCountTheSameMembers(t *testing.T) {
	// One subject bound twice (globally and on one resource) is one member
	// to both guards. If they disagreed, a cap the update allowed could
	// refuse an assignment for a subject who already holds the role, or the
	// other way round.
	s := memory.New()
	ctx := context.Background()
	r := cappedRoleWithMembers(t, s, 5, []string{"a"}, nil)
	scoped := &assignment.Assignment{
		TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: "a",
		ResourceType: "document", ResourceID: "d1",
	}
	if err := s.CreateAssignment(ctx, scoped); err != nil {
		t.Fatalf("create scoped assignment: %v", err)
	}
	h := rolesUpdateHandler(Deps{Engine: engineOver(t, s)})

	one := 1
	if _, err := h(ctx, RoleUpdateInput{ID: r.ID.String(), MaxMembers: &one}, principalFor("t1")); err != nil {
		t.Fatalf("one subject with two rows is one member, so a cap of 1 fits: %v", err)
	}
	if err := guardMemberCap(ctx, s, "t1", storedRole(t, s, r), "user", "b", time.Now()); err == nil {
		t.Error("the assignment guard let a second member into a role capped at 1")
	}
}
