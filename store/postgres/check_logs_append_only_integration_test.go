//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
)

// TestPostgres_CheckLogsAppendOnly verifies the trigger added by migration
// 20260922000005_check_logs_indexes: an UPDATE against warden_check_logs is
// rejected outright (audit integrity requires a logged decision to never
// change after the fact), while a DELETE still succeeds so retention
// (PurgeCheckLogs, DeleteCheckLogsBySubject) keeps working.
func TestPostgres_CheckLogsAppendOnly(t *testing.T) {
	s, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()
	pg := s.(*Store)

	e := &checklog.Entry{
		ID: id.NewCheckLogID(), TenantID: "t1",
		SubjectKind: "user", SubjectID: "alice", Action: "read",
		ResourceType: "doc", ResourceID: "d1", Decision: "allow",
	}
	if err := pg.CreateCheckLog(ctx, e); err != nil {
		t.Fatalf("CreateCheckLog: %v", err)
	}

	_, err := pg.pgdb.NewRaw(`UPDATE warden_check_logs SET decision = 'deny' WHERE id = $1`, e.ID.String()).Exec(ctx)
	if err == nil {
		t.Fatal("UPDATE against warden_check_logs must be rejected by the append-only trigger")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("UPDATE error = %v, want it to mention the append-only trigger", err)
	}

	got, err := pg.GetCheckLog(ctx, "t1", e.ID)
	if err != nil {
		t.Fatalf("GetCheckLog after rejected update: %v", err)
	}
	if got.Decision != "allow" {
		t.Errorf("row changed despite rejected UPDATE: decision=%q", got.Decision)
	}

	n, err := pg.DeleteCheckLogsBySubject(ctx, "t1", "user", "alice")
	if err != nil {
		t.Fatalf("DeleteCheckLogsBySubject: %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteCheckLogsBySubject: want 1 row deleted, got %d", n)
	}
}
