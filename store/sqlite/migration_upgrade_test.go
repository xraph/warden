package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/warden/id"
)

// TestSQLite_MigrationUpgrade_PreservesData is the regression test for the
// unsafe table-recreate bug: with `PRAGMA foreign_keys=ON` in effect (grove
// enables it for every sqlite connection it opens — see
// sqlitedriver.SqliteDB.Open), a migration that recreates warden_roles or
// warden_role_permissions by dropping and rebuilding the table can cascade
// or fail depending on FK enforcement, unless it's done with foreign keys
// disabled for the duration. recreateTable in migrations.go is the fix.
//
// grove's migrate.Orchestrator has no "migrate to version X" API (confirmed
// by reading github.com/xraph/grove/migrate@v1.6.3: Migrate always runs
// every pending migration in the group), so this test reaches into the
// registered Migrations group and runs each migration's Up function
// directly, in version order, up to and including 20240101000008 — the
// exact "create_*" migrations that predate any table recreate. That leaves
// the database on the original schema (warden_roles with a parent_id
// column and no namespace_path; warden_role_permissions keyed on
// (role_id, permission_id)), which is the state the later recreate
// migrations have to run against safely.
func TestSQLite_MigrationUpgrade_PreservesData(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "warden.db")

	drv := sqlitedriver.New()
	if err := drv.Open(ctx, dbPath); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = drv.Close() })

	// Apply the early, pre-recreate schema by running each migration's Up
	// directly (no orchestrator bookkeeping — this is a hand-rolled partial
	// migrate, not a real Migrate() call).
	rawExec := sqlitemigrate.New(drv)
	const cutoff = "20240101000008"
	var earlyApplied int
	for _, m := range Migrations.Migrations() {
		if m.Version > cutoff {
			continue
		}
		if err := m.Up(ctx, rawExec); err != nil {
			t.Fatalf("apply early migration %s (%s): %v", m.Version, m.Name, err)
		}
		earlyApplied++
	}
	if earlyApplied == 0 {
		t.Fatal("no early migrations matched the cutoff; test setup is broken")
	}

	// Seed rows directly against the pre-recreate schema: 2 roles, 3
	// assignments, 2 role-permission rows (warden_role_permissions here is
	// still (role_id, permission_id), not the natural-key form).
	roleIDs := []string{id.NewRoleID().String(), id.NewRoleID().String()}
	for i, rid := range roleIDs {
		if _, err := drv.Exec(ctx,
			`INSERT INTO warden_roles (id, tenant_id, name, slug) VALUES (?, ?, ?, ?)`,
			rid, "t1", "Role "+string(rune('A'+i)), "slug-"+string(rune('a'+i)),
		); err != nil {
			t.Fatalf("seed role %d: %v", i, err)
		}
	}

	permIDs := []string{id.NewPermissionID().String(), id.NewPermissionID().String()}
	for i, pid := range permIDs {
		if _, err := drv.Exec(ctx,
			`INSERT INTO warden_permissions (id, tenant_id, name, resource, action) VALUES (?, ?, ?, ?, ?)`,
			pid, "t1", "perm-"+string(rune('a'+i)), "doc", "read",
		); err != nil {
			t.Fatalf("seed permission %d: %v", i, err)
		}
	}

	for i := range 3 {
		if _, err := drv.Exec(ctx,
			`INSERT INTO warden_assignments (id, tenant_id, role_id, subject_kind, subject_id) VALUES (?, ?, ?, ?, ?)`,
			id.NewAssignmentID().String(), "t1", roleIDs[i%len(roleIDs)], "user", "subject-"+string(rune('a'+i)),
		); err != nil {
			t.Fatalf("seed assignment %d: %v", i, err)
		}
	}

	for i := range 2 {
		if _, err := drv.Exec(ctx,
			`INSERT INTO warden_role_permissions (role_id, permission_id) VALUES (?, ?)`,
			roleIDs[i], permIDs[i],
		); err != nil {
			t.Fatalf("seed role_permission %d: %v", i, err)
		}
	}

	// Now run the real, full Migrate — this is where the unsafe recreate
	// bug bites: warden_roles and warden_role_permissions each get
	// recreated at least once on the way to the current schema.
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	s := New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var rolesCount, assignmentsCount, rolePermsCount int
	if row := drv.QueryRow(ctx, `SELECT COUNT(*) FROM warden_roles`); true {
		if err := row.Scan(&rolesCount); err != nil {
			t.Fatalf("count roles: %v", err)
		}
	}
	if row := drv.QueryRow(ctx, `SELECT COUNT(*) FROM warden_assignments`); true {
		if err := row.Scan(&assignmentsCount); err != nil {
			t.Fatalf("count assignments: %v", err)
		}
	}
	if row := drv.QueryRow(ctx, `SELECT COUNT(*) FROM warden_role_permissions`); true {
		if err := row.Scan(&rolePermsCount); err != nil {
			t.Fatalf("count role_permissions: %v", err)
		}
	}

	if rolesCount != 2 {
		t.Errorf("warden_roles: want 2 rows after full Migrate, got %d", rolesCount)
	}
	if assignmentsCount != 3 {
		t.Errorf("warden_assignments: want 3 rows after full Migrate, got %d", assignmentsCount)
	}
	if rolePermsCount != 2 {
		t.Errorf("warden_role_permissions: want 2 rows after full Migrate, got %d", rolePermsCount)
	}
}
