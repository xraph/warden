package contract

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
)

// RunExpiryContract asserts that an expired assignment is invisible to the
// role-resolution paths on the Check() hot path, while a not-yet-expired or
// never-expiring assignment stays visible.
//
// The bug this guards: ListRolesForSubject and ListRolesForSubjectOnResource
// used to return every assignment row regardless of ExpiresAt, so a role
// granted "until Friday" kept granting access indefinitely once Friday
// passed, unless a separate cron sweep happened to call
// DeleteExpiredAssignments first. The fix pushes the expiry predicate into
// the query itself: `expires_at IS NULL OR expires_at > now`.
func RunExpiryContract(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("ListRolesForSubject", func(t *testing.T) { runExpiryListRolesForSubject(t, mk) })
	t.Run("ListRolesForSubjectOnResource", func(t *testing.T) { runExpiryListRolesForSubjectOnResource(t, mk) })
}

func runExpiryListRolesForSubject(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	past := time.Now().UTC().Add(-1 * time.Minute)
	future := time.Now().UTC().Add(1 * time.Hour)

	expiredRole := seedRole(t, s, "t1", "", "expiry-expired")
	activeRole := seedRole(t, s, "t1", "", "expiry-active")
	foreverRole := seedRole(t, s, "t1", "", "expiry-forever")

	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: expiredRole, SubjectKind: "user", SubjectID: "alice",
		ExpiresAt: &past,
	})
	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: activeRole, SubjectKind: "user", SubjectID: "alice",
		ExpiresAt: &future,
	})
	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: foreverRole, SubjectKind: "user", SubjectID: "alice",
	})

	got, err := s.ListRolesForSubject(ctx, "t1", nil, "user", "alice")
	if err != nil {
		t.Fatalf("ListRolesForSubject: %v", err)
	}
	assertRoleExpirySet(t, got, expiredRole, activeRole, foreverRole)
}

func runExpiryListRolesForSubjectOnResource(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	past := time.Now().UTC().Add(-1 * time.Minute)
	future := time.Now().UTC().Add(1 * time.Hour)

	expiredRole := seedRole(t, s, "t1", "", "expiry-res-expired")
	activeRole := seedRole(t, s, "t1", "", "expiry-res-active")
	foreverRole := seedRole(t, s, "t1", "", "expiry-res-forever")

	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: expiredRole, SubjectKind: "user", SubjectID: "bob",
		ResourceType: "doc", ResourceID: "d1", ExpiresAt: &past,
	})
	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: activeRole, SubjectKind: "user", SubjectID: "bob",
		ResourceType: "doc", ResourceID: "d1", ExpiresAt: &future,
	})
	createAssignment(t, s, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: foreverRole, SubjectKind: "user", SubjectID: "bob",
		ResourceType: "doc", ResourceID: "d1",
	})

	got, err := s.ListRolesForSubjectOnResource(ctx, "t1", nil, "user", "bob", "doc", "d1")
	if err != nil {
		t.Fatalf("ListRolesForSubjectOnResource: %v", err)
	}
	assertRoleExpirySet(t, got, expiredRole, activeRole, foreverRole)
}

func assertRoleExpirySet(t *testing.T, got []id.RoleID, expiredRole, activeRole, foreverRole id.RoleID) {
	t.Helper()
	set := make(map[string]bool, len(got))
	for _, r := range got {
		set[r.String()] = true
	}
	if set[expiredRole.String()] {
		t.Errorf("role %s expired a minute ago; must not be present", expiredRole)
	}
	if !set[activeRole.String()] {
		t.Errorf("role %s expires an hour from now; must be present", activeRole)
	}
	if !set[foreverRole.String()] {
		t.Errorf("role %s never expires; must be present", foreverRole)
	}
}
