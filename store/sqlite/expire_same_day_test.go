package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
)

// TestSQLite_DeleteExpiredAssignments_SameUTCDay is the regression test for
// the unwrapped-time bug: DeleteExpiredAssignments compared `expires_at`
// (stored as sqliteTime/RFC3339Nano text) against a bare time.Time bind
// argument instead of sqliteTime(now). Whatever format the sqlite driver
// falls back to for a raw time.Time doesn't necessarily lexically compare
// the way RFC3339Nano text does, and the mismatch is easiest to hit when
// both timestamps fall on the same UTC day (large date-only differences
// tend to still sort correctly by accident; same-day, different-format
// timestamps are where lexical comparison breaks first).
func TestSQLite_DeleteExpiredAssignments_SameUTCDay(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "warden.db")

	drv := sqlitedriver.New()
	if err := drv.Open(ctx, dbPath); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = drv.Close() })

	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	s := New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	r := &role.Role{TenantID: "t1", Name: "Expiring", Slug: "expiring"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	now := time.Now().UTC()
	expired := now.Add(-1 * time.Minute)
	a := &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: r.ID, SubjectKind: "user", SubjectID: "alice",
		ExpiresAt: &expired,
	}
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}

	n, err := s.DeleteExpiredAssignments(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpiredAssignments: %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteExpiredAssignments: want 1 row deleted, got %d", n)
	}

	if _, err := s.GetAssignment(ctx, "t1", a.ID); err == nil {
		t.Errorf("assignment expired a minute ago on the same UTC day survived DeleteExpiredAssignments")
	}
}
