package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xraph/grove/driver"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/warden/id"
)

// foreignKeysStayOn wraps an Executor and swallows PRAGMA foreign_keys=OFF,
// which is exactly what happens when that statement lands on a different
// pooled connection than the DDL that follows: enforcement stays on for
// the connection doing the DROP TABLE.
type foreignKeysStayOn struct{ migrate.Executor }

func (f foreignKeysStayOn) Exec(ctx context.Context, q string, args ...any) (driver.Result, error) {
	if strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(q), " ", ""), "PRAGMAforeign_keys=OFF") {
		return nil, nil
	}
	return f.Executor.Exec(ctx, q, args...)
}

// seededEarlySchema opens a database on the pre-recreate schema and seeds 2
// roles, 3 assignments and 2 role-permission rows.
func seededEarlySchema(t *testing.T) (*sqlitedriver.SqliteDB, migrate.Executor) {
	t.Helper()
	ctx := context.Background()
	drv := sqlitedriver.New()
	if err := drv.Open(ctx, filepath.Join(t.TempDir(), "guard.db")); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = drv.Close() })

	exec := sqlitemigrate.New(drv)
	for _, m := range Migrations.Migrations() {
		if m.Version > "20240101000008" {
			continue
		}
		if err := m.Up(ctx, exec); err != nil {
			t.Fatalf("apply %s: %v", m.Name, err)
		}
	}

	roleIDs := []string{id.NewRoleID().String(), id.NewRoleID().String()}
	permIDs := []string{id.NewPermissionID().String(), id.NewPermissionID().String()}
	for i, rid := range roleIDs {
		mustExec(t, drv, `INSERT INTO warden_roles (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)`, rid, "t1", "R", "slug-"+string(rune('a'+i)))
	}
	for i, pid := range permIDs {
		mustExec(t, drv, `INSERT INTO warden_permissions (id, tenant_id, name, resource, action) VALUES (?, ?, ?, ?, ?)`, pid, "t1", "p"+string(rune('a'+i)), "doc", "read")
	}
	for i := range 3 {
		mustExec(t, drv, `INSERT INTO warden_assignments (id, tenant_id, role_id, subject_kind, subject_id) VALUES (?, ?, ?, ?, ?)`,
			id.NewAssignmentID().String(), "t1", roleIDs[i%2], "user", "s"+string(rune('a'+i)))
	}
	for i := range 2 {
		mustExec(t, drv, `INSERT INTO warden_role_permissions (role_id, permission_id) VALUES (?, ?)`, roleIDs[i], permIDs[i])
	}
	return drv, exec
}

func mustExec(t *testing.T, drv *sqlitedriver.SqliteDB, q string, args ...any) {
	t.Helper()
	if _, err := drv.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func countRows(t *testing.T, drv *sqlitedriver.SqliteDB, table string) int {
	t.Helper()
	var n int
	if err := drv.QueryRow(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// recreateRoles rebuilds warden_roles with the same columns and its primary
// key, the way the real recreate migrations do, so the tables that
// reference it stay valid.
const recreateRoles = `
CREATE TABLE warden_roles_new (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    slug            TEXT NOT NULL,
    is_system       INTEGER NOT NULL DEFAULT 0,
    is_default      INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    max_members     INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tenant_id, slug)
);
INSERT INTO warden_roles_new SELECT id, tenant_id, app_id, name, description, slug, is_system, is_default, parent_id, max_members, metadata, created_at, updated_at FROM warden_roles;
DROP TABLE warden_roles;
ALTER TABLE warden_roles_new RENAME TO warden_roles;
`

// TestRecreateTable_RefusesWhenForeignKeysAreStillOn is the guard for the
// failure recreateTable exists to prevent. If the PRAGMA lands on another
// connection, DROP TABLE warden_roles cascades through
// warden_assignments, and PRAGMA foreign_key_check then passes because
// the referencing rows are already gone. The guard has to notice foreign
// keys are on, and roll back so nothing is lost.
func TestRecreateTable_RefusesWhenForeignKeysAreStillOn(t *testing.T) {
	ctx := context.Background()
	drv, exec := seededEarlySchema(t)

	err := recreateTable(ctx, foreignKeysStayOn{exec}, recreateRoles, "warden_assignments", "warden_role_permissions")
	if err == nil {
		t.Fatal("recreateTable succeeded with foreign keys enforced")
	}
	if !strings.Contains(err.Error(), "foreign keys") {
		t.Errorf("error = %v, want it to name foreign keys", err)
	}
	if got := countRows(t, drv, "warden_assignments"); got != 3 {
		t.Errorf("warden_assignments has %d rows after the refusal, want 3", got)
	}
	if got := countRows(t, drv, "warden_role_permissions"); got != 2 {
		t.Errorf("warden_role_permissions has %d rows after the refusal, want 2", got)
	}
	if got := countRows(t, drv, "warden_roles"); got != 2 {
		t.Errorf("warden_roles has %d rows after the refusal, want 2", got)
	}
}

// TestRecreateTable_RollsBackWhenAGuardedTableLosesRows covers the case the
// PRAGMA read cannot: whatever the reason, a guarded table came out of the
// DDL with fewer rows than it went in with.
func TestRecreateTable_RollsBackWhenAGuardedTableLosesRows(t *testing.T) {
	ctx := context.Background()
	drv, exec := seededEarlySchema(t)

	err := recreateTable(ctx, exec, `DELETE FROM warden_assignments;`, "warden_assignments")
	if err == nil {
		t.Fatal("recreateTable committed a body that deleted guarded rows")
	}
	if !strings.Contains(err.Error(), "warden_assignments") {
		t.Errorf("error = %v, want it to name warden_assignments", err)
	}
	if got := countRows(t, drv, "warden_assignments"); got != 3 {
		t.Errorf("warden_assignments has %d rows after the rollback, want 3", got)
	}
}

func TestRecreateTable_CommitsAValidRecreate(t *testing.T) {
	ctx := context.Background()
	drv, exec := seededEarlySchema(t)

	if err := recreateTable(ctx, exec, recreateRoles, "warden_assignments", "warden_role_permissions"); err != nil {
		t.Fatalf("recreateTable: %v", err)
	}
	if got := countRows(t, drv, "warden_assignments"); got != 3 {
		t.Errorf("warden_assignments has %d rows, want 3", got)
	}
	if got := countRows(t, drv, "warden_roles"); got != 2 {
		t.Errorf("warden_roles has %d rows, want 2", got)
	}
}
