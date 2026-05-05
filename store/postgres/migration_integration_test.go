//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	_ "github.com/xraph/grove/drivers/pgdriver/pgmigrate"
)

// TestMigration_NamespaceScopedUniqueness verifies migration
// 20260201000001 by inspecting pg_constraint after a fresh migration:
//
//   - Old per-tenant constraints (warden_roles_tenant_id_slug_key, etc.)
//     are dropped.
//   - New per-(tenant, namespace) constraints (warden_roles_scope_slug_key,
//     etc.) exist and cover the right columns in the right order.
//
// Catches regressions where someone re-orders the migration's ALTER
// TABLE statements or uses the wrong column set.
func TestMigration_NamespaceScopedUniqueness(t *testing.T) {
	admin := adminDSN(t)
	dbName := freshDBName(t)
	ctx := context.Background()
	if err := createDatabase(ctx, admin, dbName); err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer func() { _ = dropDatabase(admin, dbName) }()

	// Migrate via the standard path so we exercise the real registration order.
	dsn := replaceDBName(admin, dbName)
	drv := pgdriver.New()
	if err := drv.Open(ctx, dsn); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer drv.Close()
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	if err := New(db).Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Inspect via a separate pgx connection (grove's PgDB doesn't expose
	// the pool, and we want to ask the DB directly anyway).
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("inspect connect: %v", err)
	}
	defer conn.Close(ctx)

	// 1. Every old per-tenant constraint must be gone.
	oldNames := []string{
		"warden_roles_tenant_id_slug_key",
		"warden_permissions_tenant_id_name_key",
		"warden_policies_tenant_id_name_key",
		"warden_resource_types_tenant_id_name_key",
		"warden_assignments_tenant_id_role_id_subject_kind_subject_i_key",
	}
	for _, name := range oldNames {
		if constraintExists(t, conn, ctx, name) {
			t.Errorf("old constraint %q still present after migration", name)
		}
	}

	// 2. Every new scope-aware constraint must be present and include
	//    namespace_path in its column list at the right position.
	newConstraints := map[string][]string{
		"warden_roles_scope_slug_key":          {"tenant_id", "namespace_path", "slug"},
		"warden_permissions_scope_name_key":    {"tenant_id", "namespace_path", "name"},
		"warden_policies_scope_name_key":       {"tenant_id", "namespace_path", "name"},
		"warden_resource_types_scope_name_key": {"tenant_id", "namespace_path", "name"},
		"warden_assignments_scope_key":         {"tenant_id", "namespace_path", "role_id", "subject_kind", "subject_id", "resource_type", "resource_id"},
	}
	for name, wantCols := range newConstraints {
		gotCols := constraintColumns(t, conn, ctx, name)
		if gotCols == nil {
			t.Errorf("new constraint %q missing", name)
			continue
		}
		if !slicesEqual(gotCols, wantCols) {
			t.Errorf("constraint %q: cols = %v, want %v", name, gotCols, wantCols)
		}
	}

	// 3. The role-parent FK should now reference (tenant_id, namespace_path,
	//    slug) instead of just (tenant_id, slug).
	gotFKCols := constraintColumns(t, conn, ctx, "warden_roles_parent_fk")
	wantFKCols := []string{"tenant_id", "namespace_path", "parent_slug"}
	if !slicesEqual(gotFKCols, wantFKCols) {
		t.Errorf("warden_roles_parent_fk: cols = %v, want %v", gotFKCols, wantFKCols)
	}
}

// constraintExists returns whether a UNIQUE/PK/FK constraint with the
// given name exists in the public schema.
func constraintExists(t *testing.T, conn *pgx.Conn, ctx context.Context, name string) bool {
	t.Helper()
	var n int
	row := conn.QueryRow(ctx,
		"SELECT count(*) FROM pg_constraint WHERE conname = $1", name)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("query pg_constraint(%s): %v", name, err)
	}
	return n > 0
}

// constraintColumns returns the ordered column names covered by a
// constraint. Returns nil if the constraint doesn't exist.
func constraintColumns(t *testing.T, conn *pgx.Conn, ctx context.Context, name string) []string {
	t.Helper()
	const q = `
SELECT a.attname
FROM pg_constraint c
JOIN unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
WHERE c.conname = $1
ORDER BY k.ord
`
	rows, err := conn.Query(ctx, q, name)
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols = append(cols, col)
	}
	if len(cols) == 0 {
		return nil
	}
	return cols
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
