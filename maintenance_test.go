package warden

import (
	"context"
	"errors"
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

// recordingCache is a Cache that records which invalidations maintenance
// asks for, so a test can tell a tenant flush from a full Clear.
type recordingCache struct {
	tenants []string
	clears  int
}

func (c *recordingCache) Get(context.Context, string, string, *CheckRequest) (*CheckResult, bool) {
	return nil, false
}
func (c *recordingCache) Set(context.Context, string, string, *CheckRequest, *CheckResult) {}
func (c *recordingCache) InvalidateTenant(_ context.Context, tenantID string) {
	c.tenants = append(c.tenants, tenantID)
}
func (c *recordingCache) InvalidateSubject(context.Context, string, SubjectKind, string) {}
func (c *recordingCache) Clear(context.Context)                                          { c.clears++ }

// tenantMaintenanceEngine seeds t1 and t2 with one expired assignment and
// one check log entry past a 24 hour retention each, on a fixed clock.
func tenantMaintenanceEngine(t *testing.T, c Cache) (*Engine, *memory.Store) {
	t.Helper()
	ctx := context.Background()
	s := memory.New()
	cfg := DefaultConfig()
	cfg.CheckLogRetention = 24 * time.Hour
	cfg.EnableCheckLog = boolPtr(false)
	eng, err := NewEngine(WithStore(s), WithCache(c), WithConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	eng.nowFn = fakeClock(now)
	past := now.Add(-time.Hour)
	for _, tenant := range []string{"t1", "t2"} {
		if err := s.CreateAssignment(ctx, &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: tenant, RoleID: id.NewRoleID(),
			SubjectKind: "user", SubjectID: "expired", ExpiresAt: &past,
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateCheckLog(ctx, &checklog.Entry{
			ID: id.NewCheckLogID(), TenantID: tenant, CreatedAt: now.Add(-48 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return eng, s
}

func TestRunTenantMaintenance_PurgesOnlyThatTenantAndInvalidatesOnlyItsCache(t *testing.T) {
	ctx := context.Background()
	c := &recordingCache{}
	eng, s := tenantMaintenanceEngine(t, c)

	report, err := eng.RunTenantMaintenance(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if report.AssignmentsPurged != 1 || report.CheckLogsPurged != 1 {
		t.Fatalf("report = %+v, want one assignment and one check log (t1's only)", report)
	}

	if n, _ := s.CountAssignments(ctx, &assignment.ListFilter{TenantID: "t2"}); n != 1 {
		t.Errorf("t2 has %d assignments after t1's run, want its 1 untouched", n)
	}
	if n, _ := s.CountCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t2"}); n != 1 {
		t.Errorf("t2 has %d check logs after t1's run, want its 1 untouched", n)
	}

	if c.clears != 0 {
		t.Errorf("RunTenantMaintenance called Clear %d times; it must flush only the tenant", c.clears)
	}
	if len(c.tenants) != 1 || c.tenants[0] != "t1" {
		t.Errorf("InvalidateTenant calls = %q, want exactly [t1]", c.tenants)
	}
}

func TestRunTenantMaintenance_LeavesTheCacheAloneWhenNothingWasPurged(t *testing.T) {
	ctx := context.Background()
	c := &recordingCache{}
	eng, _ := tenantMaintenanceEngine(t, c)

	if _, err := eng.RunTenantMaintenance(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	c.tenants, c.clears = nil, 0

	report, err := eng.RunTenantMaintenance(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if report.AssignmentsPurged != 0 || report.CheckLogsPurged != 0 {
		t.Fatalf("second run report = %+v, want zero", report)
	}
	if c.clears != 0 || len(c.tenants) != 0 {
		t.Errorf("a run that purged nothing invalidated the cache: clears=%d tenants=%q", c.clears, c.tenants)
	}
}

func TestRunTenantMaintenance_RefusesAnEmptyTenant(t *testing.T) {
	ctx := context.Background()
	c := &recordingCache{}
	eng, s := tenantMaintenanceEngine(t, c)

	if _, err := eng.RunTenantMaintenance(ctx, ""); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("err = %v, want ErrTenantRequired", err)
	}
	for _, tenant := range []string{"t1", "t2"} {
		if n, _ := s.CountAssignments(ctx, &assignment.ListFilter{TenantID: tenant}); n != 1 {
			t.Errorf("an empty-tenant run removed %s's assignment", tenant)
		}
	}
	if c.clears != 0 || len(c.tenants) != 0 {
		t.Errorf("an empty-tenant run invalidated the cache: clears=%d tenants=%q", c.clears, c.tenants)
	}
}

func TestRunMaintenance_StillPurgesEveryTenantAndClears(t *testing.T) {
	ctx := context.Background()
	c := &recordingCache{}
	eng, _ := tenantMaintenanceEngine(t, c)

	report, err := eng.RunMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.AssignmentsPurged != 2 || report.CheckLogsPurged != 2 {
		t.Fatalf("report = %+v, want both tenants' rows", report)
	}
	if c.clears != 1 || len(c.tenants) != 0 {
		t.Errorf("RunMaintenance: clears=%d tenants=%q, want one Clear and no tenant flush", c.clears, c.tenants)
	}
}
