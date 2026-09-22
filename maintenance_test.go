package warden

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/store/memory"
)

// fakeClock returns a fixed instant, letting RunMaintenance tests control
// exactly what counts as "expired" without sleeping.
func fakeClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestRunMaintenance_PurgesExpiredAssignments(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: "expired", ExpiresAt: &past,
	})
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: "still-good", ExpiresAt: &future,
	})
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: "no-expiry",
	})

	eng.nowFn = fakeClock(now)

	report, err := eng.RunMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.AssignmentsPurged != 1 {
		t.Fatalf("expected 1 assignment purged, got %d", report.AssignmentsPurged)
	}
}

func TestRunMaintenance_PurgesOldCheckLogsByRetention(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithConfig(func() Config {
		c := DefaultConfig()
		c.CheckLogRetention = 24 * time.Hour
		c.EnableCheckLog = boolPtr(false) // writer disabled; we seed logs directly.
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-time.Hour)

	_ = s.CreateCheckLog(ctx, &checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1", CreatedAt: old})
	_ = s.CreateCheckLog(ctx, &checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1", CreatedAt: recent})

	eng.nowFn = fakeClock(now)

	report, err := eng.RunMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.CheckLogsPurged != 1 {
		t.Fatalf("expected 1 check log purged, got %d", report.CheckLogsPurged)
	}
}

func TestRunMaintenance_ZeroRetentionDisablesCheckLogPurge(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithConfig(func() Config {
		c := DefaultConfig()
		c.CheckLogRetention = 0
		c.EnableCheckLog = boolPtr(false)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = s.CreateCheckLog(ctx, &checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1", CreatedAt: old})

	report, err := eng.RunMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.CheckLogsPurged != 0 {
		t.Fatalf("expected 0 check logs purged when retention is 0, got %d", report.CheckLogsPurged)
	}
}

func TestRunMaintenance_ClearsCacheWhenSomethingWasPurged(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	c := NewMemoryCache()
	eng, err := NewEngine(WithStore(s), WithCache(c))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: "expired", ExpiresAt: &past,
	})

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	c.Set(ctx, "t1", "", req, &CheckResult{Allowed: true})

	eng.nowFn = fakeClock(now)
	if _, err := eng.RunMaintenance(ctx); err != nil {
		t.Fatal(err)
	}

	if _, ok := c.Get(ctx, "t1", "", req); ok {
		t.Fatal("expected cache to be cleared after maintenance purged rows")
	}
}

func TestStartMaintenance_RunsOnInterval(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithConfig(func() Config {
		c := DefaultConfig()
		c.MaintenanceInterval = 10 * time.Millisecond
		c.EnableCheckLog = boolPtr(false)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	past := now.Add(-time.Hour)
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: "expired", ExpiresAt: &past,
	})

	runCtx, cancel := context.WithCancel(ctx)
	eng.StartMaintenance(runCtx)
	defer cancel()

	deadline := time.After(2 * time.Second)
	for {
		count, err := s.CountAssignments(ctx, &assignment.ListFilter{TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("StartMaintenance did not purge the expired assignment in time")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func boolPtr(b bool) *bool { return &b }
