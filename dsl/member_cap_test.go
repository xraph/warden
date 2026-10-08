package dsl

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// seedCappedRole stores role "small" (named "Small") in tenant t1 with the
// given cap, and binds one live user per name in live and one expired user
// per name in expired.
func seedCappedRole(t *testing.T, s *memory.Store, maxMembers int, live, expired []string) {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: maxMembers}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	bind := func(who string, expires *time.Time) {
		if err := s.CreateAssignment(ctx, &assignment.Assignment{
			TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: who, ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("assign %q: %v", who, err)
		}
	}
	for _, who := range live {
		bind(who, nil)
	}
	for _, who := range expired {
		bind(who, &past)
	}
}

// smallRoleSource declares role small with the given name, description and
// cap. A cap of 0 leaves max_members out, which is how source says
// unlimited.
func smallRoleSource(name, description string, maxMembers int) string {
	src := fmt.Sprintf("warden config 1\ntenant t1\n\nrole small {\n    name = %q\n    description = %q\n", name, description)
	if maxMembers != 0 {
		src += fmt.Sprintf("    max_members = %d\n", maxMembers)
	}
	return src + "}\n"
}

func storedSmall(t *testing.T, s *memory.Store) *role.Role {
	t.Helper()
	got, err := s.GetRoleBySlug(context.Background(), "t1", "", "small")
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	return got
}

func TestApply_RefusesACapBelowTheLiveMemberCount(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		t.Run(fmt.Sprintf("dryRun=%v", dryRun), func(t *testing.T) {
			eng, s := newTestEngine(t)
			seedCappedRole(t, s, 5, []string{"a", "b", "c"}, nil)

			prog := mustParse(t, smallRoleSource("Small", "edited", 2))
			res, err := Apply(context.Background(), eng, prog, ApplyOptions{DryRun: dryRun})
			var capErr *assignment.CapBelowMembersError
			if !errors.As(err, &capErr) {
				t.Fatalf("want a CapBelowMembersError, got %v", err)
			}
			if want := `"Small" has 3 members, so its cap cannot be lowered to 2`; capErr.Error() != want {
				t.Errorf("message = %q, want %q", capErr.Error(), want)
			}
			if res != nil && len(res.Updated) != 0 {
				t.Errorf("the result reports a write that did not happen: %v", res.Updated)
			}
			if after := storedSmall(t, s); after.MaxMembers != 5 || after.Description != "" {
				t.Errorf("the refusal wrote something: cap %d, description %q", after.MaxMembers, after.Description)
			}
		})
	}
}

func TestApply_RefusesACapOnAnUncappedRoleBelowItsMembers(t *testing.T) {
	eng, s := newTestEngine(t)
	seedCappedRole(t, s, 0, []string{"a", "b"}, nil)

	_, err := Apply(context.Background(), eng, mustParse(t, smallRoleSource("Small", "", 1)), ApplyOptions{})
	var capErr *assignment.CapBelowMembersError
	if !errors.As(err, &capErr) {
		t.Fatalf("want a CapBelowMembersError, got %v", err)
	}
	if after := storedSmall(t, s); after.MaxMembers != 0 {
		t.Errorf("cap = %d, want 0 (unchanged)", after.MaxMembers)
	}
}

func TestApply_SavesACapAtOrAboveTheLiveCountOrCleared(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newCap int
	}{
		{"exactly the live count", 3},
		{"raised", 10},
		{"cleared to unlimited", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng, s := newTestEngine(t)
			seedCappedRole(t, s, 5, []string{"a", "b", "c"}, nil)

			if _, err := Apply(context.Background(), eng, mustParse(t, smallRoleSource("Small", "", tc.newCap)), ApplyOptions{}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if after := storedSmall(t, s); after.MaxMembers != tc.newCap {
				t.Errorf("cap = %d, want %d", after.MaxMembers, tc.newCap)
			}
		})
	}
}

func TestApply_CapDoesNotCountExpiredAssignments(t *testing.T) {
	eng, s := newTestEngine(t)
	seedCappedRole(t, s, 5, []string{"a", "b"}, []string{"old1", "old2"})
	ctx := context.Background()

	_, err := Apply(ctx, eng, mustParse(t, smallRoleSource("Small", "", 1)), ApplyOptions{})
	var capErr *assignment.CapBelowMembersError
	if !errors.As(err, &capErr) || capErr.Members != 2 {
		t.Fatalf("lowering to 1: want the refusal counting 2 live members, got %v", err)
	}
	if _, err := Apply(ctx, eng, mustParse(t, smallRoleSource("Small", "", 2)), ApplyOptions{}); err != nil {
		t.Fatalf("lowering to the live count: %v", err)
	}
	if after := storedSmall(t, s); after.MaxMembers != 2 {
		t.Errorf("cap = %d, want 2", after.MaxMembers)
	}
}

func TestApply_EditsAnOverFullRoleWhenTheCapIsUnchanged(t *testing.T) {
	eng, s := newTestEngine(t)
	seedCappedRole(t, s, 1, []string{"a", "b", "c"}, nil)

	if _, err := Apply(context.Background(), eng, mustParse(t, smallRoleSource("Renamed", "edited", 1)), ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if after := storedSmall(t, s); after.Name != "Renamed" || after.Description != "edited" || after.MaxMembers != 1 {
		t.Errorf("stored name %q description %q cap %d, want Renamed, edited, 1", after.Name, after.Description, after.MaxMembers)
	}
}
