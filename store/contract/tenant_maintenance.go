// tenant_maintenance.go: the tenant-scoped maintenance purges remove one
// tenant's rows and nothing else.
//
// The dashboard's maintenance.run is a tenant's command. Before these
// methods existed it called the engine-wide purges, so any tenant's
// operator could delete every tenant's expired assignments and old check
// log entries. DeleteExpiredAssignmentsForTenant and PurgeCheckLogsForTenant
// carry the tenant into the delete itself. An empty tenant ID is refused:
// on these stores an empty tenant filter matches every row (see
// RunEmptyTenantContract), so passing one through would quietly turn a
// tenant purge back into the engine-wide one.
package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/wardenerr"
)

// tenantMaintenanceSeed is one tenant's rows: an expired and a live
// assignment, and a check log entry on each side of the cutoff.
type tenantMaintenanceSeed struct {
	expired, live  id.AssignmentID
	oldLog, newLog id.CheckLogID
}

func seedTenantMaintenance(t *testing.T, s store.Store, tenantID string, now, cutoff time.Time) tenantMaintenanceSeed {
	t.Helper()
	ctx := context.Background()

	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	roleID := seedRole(t, s, tenantID, "", "maint-"+tenantID)

	seed := tenantMaintenanceSeed{
		expired: id.NewAssignmentID(),
		live:    id.NewAssignmentID(),
		oldLog:  id.NewCheckLogID(),
		newLog:  id.NewCheckLogID(),
	}
	createAssignment(t, s, &assignment.Assignment{
		ID: seed.expired, TenantID: tenantID, RoleID: roleID,
		SubjectKind: "user", SubjectID: "expired", ExpiresAt: &past,
	})
	createAssignment(t, s, &assignment.Assignment{
		ID: seed.live, TenantID: tenantID, RoleID: roleID,
		SubjectKind: "user", SubjectID: "live", ExpiresAt: &future,
	})

	for _, e := range []*checklog.Entry{
		{ID: seed.oldLog, CreatedAt: cutoff.Add(-time.Hour)},
		{ID: seed.newLog, CreatedAt: cutoff.Add(time.Hour)},
	} {
		e.TenantID = tenantID
		e.SubjectKind, e.SubjectID = "user", "alice"
		e.Action, e.ResourceType, e.ResourceID = "read", "doc", "d1"
		e.Decision = "allow"
		if err := s.CreateCheckLog(ctx, e); err != nil {
			t.Fatalf("create check log in %s: %v", tenantID, err)
		}
	}
	return seed
}

func assignmentExists(t *testing.T, s store.Store, tenantID string, aid id.AssignmentID) bool {
	t.Helper()
	_, err := s.GetAssignment(context.Background(), tenantID, aid)
	switch {
	case err == nil:
		return true
	case errors.Is(err, wardenerr.ErrAssignmentNotFound):
		return false
	default:
		t.Fatalf("GetAssignment(%s, %s): %v", tenantID, aid, err)
		return false
	}
}

func checkLogExists(t *testing.T, s store.Store, tenantID string, lid id.CheckLogID) bool {
	t.Helper()
	_, err := s.GetCheckLog(context.Background(), tenantID, lid)
	switch {
	case err == nil:
		return true
	case errors.Is(err, wardenerr.ErrCheckLogNotFound):
		return false
	default:
		t.Fatalf("GetCheckLog(%s, %s): %v", tenantID, lid, err)
		return false
	}
}

// RunTenantMaintenanceContract seeds two tenants, each with an expired and a
// live assignment and a check log entry either side of the cutoff, runs both
// tenant purges for t1, and proves only t1's expired assignment and old
// entry are gone while every t2 row survives. An empty tenant ID is an
// error and deletes nothing.
func RunTenantMaintenanceContract(t *testing.T, mk MakeStore) {
	setup := func(t *testing.T) (store.Store, func(), time.Time, time.Time, tenantMaintenanceSeed, tenantMaintenanceSeed) {
		s, cleanup := mk(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		cutoff := now.Add(-24 * time.Hour)
		t1 := seedTenantMaintenance(t, s, "maint-t1", now, cutoff)
		t2 := seedTenantMaintenance(t, s, "maint-t2", now, cutoff)
		return s, cleanup, now, cutoff, t1, t2
	}

	t.Run("purges only the named tenant", func(t *testing.T) {
		s, cleanup, now, cutoff, t1, t2 := setup(t)
		defer cleanup()
		ctx := context.Background()

		n, err := s.DeleteExpiredAssignmentsForTenant(ctx, "maint-t1", now)
		if err != nil {
			t.Fatalf("DeleteExpiredAssignmentsForTenant: %v", err)
		}
		if n != 1 {
			t.Errorf("DeleteExpiredAssignmentsForTenant removed %d rows, want 1 (t1's expired assignment only)", n)
		}
		n, err = s.PurgeCheckLogsForTenant(ctx, "maint-t1", cutoff)
		if err != nil {
			t.Fatalf("PurgeCheckLogsForTenant: %v", err)
		}
		if n != 1 {
			t.Errorf("PurgeCheckLogsForTenant removed %d rows, want 1 (t1's old entry only)", n)
		}

		if assignmentExists(t, s, "maint-t1", t1.expired) {
			t.Error("t1's expired assignment survived its tenant's purge")
		}
		if !assignmentExists(t, s, "maint-t1", t1.live) {
			t.Error("t1's live assignment was purged")
		}
		if checkLogExists(t, s, "maint-t1", t1.oldLog) {
			t.Error("t1's check log entry older than the cutoff survived its tenant's purge")
		}
		if !checkLogExists(t, s, "maint-t1", t1.newLog) {
			t.Error("t1's check log entry newer than the cutoff was purged")
		}

		if !assignmentExists(t, s, "maint-t2", t2.expired) {
			t.Error("t1's purge deleted t2's expired assignment")
		}
		if !assignmentExists(t, s, "maint-t2", t2.live) {
			t.Error("t1's purge deleted t2's live assignment")
		}
		if !checkLogExists(t, s, "maint-t2", t2.oldLog) {
			t.Error("t1's purge deleted t2's old check log entry")
		}
		if !checkLogExists(t, s, "maint-t2", t2.newLog) {
			t.Error("t1's purge deleted t2's new check log entry")
		}
	})

	t.Run("an empty tenant is refused and deletes nothing", func(t *testing.T) {
		s, cleanup, now, cutoff, t1, t2 := setup(t)
		defer cleanup()
		ctx := context.Background()

		if n, err := s.DeleteExpiredAssignmentsForTenant(ctx, "", now); !errors.Is(err, wardenerr.ErrTenantRequired) {
			t.Errorf("DeleteExpiredAssignmentsForTenant with an empty tenant: n=%d err=%v, want ErrTenantRequired", n, err)
		}
		if n, err := s.PurgeCheckLogsForTenant(ctx, "", cutoff); !errors.Is(err, wardenerr.ErrTenantRequired) {
			t.Errorf("PurgeCheckLogsForTenant with an empty tenant: n=%d err=%v, want ErrTenantRequired", n, err)
		}

		for _, seed := range []struct {
			tenant string
			rows   tenantMaintenanceSeed
		}{{"maint-t1", t1}, {"maint-t2", t2}} {
			if !assignmentExists(t, s, seed.tenant, seed.rows.expired) {
				t.Errorf("an empty-tenant purge deleted %s's expired assignment", seed.tenant)
			}
			if !checkLogExists(t, s, seed.tenant, seed.rows.oldLog) {
				t.Errorf("an empty-tenant purge deleted %s's old check log entry", seed.tenant)
			}
		}
	})
}
