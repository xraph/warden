package assignment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/warden/id"
)

type fakeLister struct {
	held  []*Assignment
	err   error
	reads int
}

func (f *fakeLister) ListSubjectsForRole(context.Context, string, id.RoleID) ([]*Assignment, error) {
	f.reads++
	return f.held, f.err
}

func TestLiveMembersCountsDistinctLiveSubjects(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	held := []*Assignment{
		{SubjectKind: "user", SubjectID: "a"},
		{SubjectKind: "user", SubjectID: "a", ResourceType: "doc", ResourceID: "1"},
		{SubjectKind: "service", SubjectID: "a"},
		{SubjectKind: "user", SubjectID: "b", ExpiresAt: &future},
		{SubjectKind: "user", SubjectID: "gone", ExpiresAt: &past},
		{SubjectKind: "user", SubjectID: "edge", ExpiresAt: &now},
	}
	got := LiveMembers(held, now)
	if len(got) != 3 {
		t.Fatalf("members = %v, want user/a, service/a and user/b", got)
	}
	for _, m := range []Member{{"user", "a"}, {"service", "a"}, {"user", "b"}} {
		if _, ok := got[m]; !ok {
			t.Errorf("missing %v", m)
		}
	}
}

func TestCheckCapLoweringReadsOnlyWhenTheCapIsLowered(t *testing.T) {
	three := []*Assignment{
		{SubjectKind: "user", SubjectID: "a"},
		{SubjectKind: "user", SubjectID: "b"},
		{SubjectKind: "user", SubjectID: "c"},
	}
	for _, tc := range []struct {
		name           string
		oldCap, newCap int
		wantRead       bool
		wantRefused    bool
	}{
		{"unchanged on an over-full role", 1, 1, false, false},
		{"raised", 1, 2, false, false},
		{"cleared", 5, 0, false, false},
		{"negative is unlimited too", 5, -1, false, false},
		{"lowered below the count", 5, 2, true, true},
		{"lowered to the count", 5, 3, true, false},
		{"unlimited to below the count", 0, 2, true, true},
		{"negative to below the count", -1, 2, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLister{held: three}
			err := CheckCapLowering(context.Background(), f, "t1", id.RoleID{}, "R", tc.oldCap, tc.newCap, time.Now())
			if (f.reads > 0) != tc.wantRead {
				t.Errorf("reads = %d, want a read: %v", f.reads, tc.wantRead)
			}
			var capErr *CapBelowMembersError
			if refused := errors.As(err, &capErr); refused != tc.wantRefused {
				t.Fatalf("err = %v, want refused: %v", err, tc.wantRefused)
			}
			if tc.wantRefused && capErr.Error() != `"R" has 3 members, so its cap cannot be lowered to 2` {
				t.Errorf("message = %q", capErr.Error())
			}
		})
	}
}

func TestCheckCapLoweringReturnsTheStoreError(t *testing.T) {
	boom := errors.New("boom")
	err := CheckCapLowering(context.Background(), &fakeLister{err: boom}, "t1", id.RoleID{}, "R", 5, 2, time.Now())
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the store error", err)
	}
}

func TestCheckMemberCapRefusesOnlyANewSubjectOnAFullRole(t *testing.T) {
	two := []*Assignment{
		{SubjectKind: "user", SubjectID: "a"},
		{SubjectKind: "user", SubjectID: "b"},
	}
	for _, tc := range []struct {
		name        string
		maxMembers  int
		subjectID   string
		wantRead    bool
		wantRefused bool
	}{
		{"uncapped", 0, "c", false, false},
		{"negative is unlimited too", -1, "c", false, false},
		{"a seat is free", 3, "c", true, false},
		{"full", 2, "c", true, true},
		{"already a member", 2, "a", true, false},
		{"already over the cap, still a member", 1, "a", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLister{held: two}
			err := CheckMemberCap(context.Background(), f, "t1", id.NewRoleID(), "Small", tc.maxMembers, "user", tc.subjectID, time.Now())
			if (f.reads > 0) != tc.wantRead {
				t.Errorf("reads = %d, want a read: %v", f.reads, tc.wantRead)
			}
			var full *RoleFullError
			if got := errors.As(err, &full); got != tc.wantRefused {
				t.Fatalf("err = %v, want refused: %v", err, tc.wantRefused)
			}
			if tc.wantRefused {
				want := `"Small" is capped at 2 members and already has 2`
				if err.Error() != want {
					t.Errorf("message = %q, want %q", err.Error(), want)
				}
			}
		})
	}
}

func TestCheckMemberCapPassesTheStoreErrorThrough(t *testing.T) {
	boom := errors.New("boom")
	err := CheckMemberCap(context.Background(), &fakeLister{err: boom}, "t1", id.NewRoleID(), "Small", 2, "user", "c", time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store error", err)
	}
}
