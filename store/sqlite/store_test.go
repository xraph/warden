package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Side-effect import: register the SQLite migration executor.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
)

// TestSQLiteStore_RoleRoundTrip is the regression test for the time.Time
// scan bug — creating a role then reading it back used to fail with
// "unsupported Scan, storing driver.Value type string into type *time.Time"
// because SQLite returns TEXT columns as strings and Go's standard time.Time
// type can't auto-Scan from a string.
//
// The fix: store/sqlite/sqlitetime.go defines a wrapper type that
// implements sql.Scanner for the multiple time formats SQLite produces
// (RFC3339Nano, RFC3339, "2006-01-02 15:04:05", etc.) and driver.Valuer
// to emit RFC3339Nano on writes for clean round-trips.
func TestSQLiteStore_RoleRoundTrip(t *testing.T) {
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

	roleID := id.NewRoleID()
	created := time.Now().UTC().Truncate(time.Microsecond)
	r := &role.Role{
		ID:        roleID,
		TenantID:  "t1",
		Name:      "Viewer",
		Slug:      "viewer",
		IsSystem:  false,
		CreatedAt: created,
		UpdatedAt: created,
	}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	// GetRole — this was the failing path before the fix.
	got, err := s.GetRole(ctx, roleID)
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.Slug != "viewer" {
		t.Errorf("slug = %q", got.Slug)
	}
	if got.CreatedAt.IsZero() {
		t.Errorf("CreatedAt was zero — time scan still broken")
	}

	// GetRoleBySlug — same scan path, exercised by the API and the engine.
	got2, err := s.GetRoleBySlug(ctx, "t1", "viewer")
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}
	if got2.ID != roleID {
		t.Errorf("ID mismatch: %s vs %s", got2.ID, roleID)
	}

	// ListRoles — also a scan path.
	roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("expected 1 role, got %d", len(roles))
	}
}

// TestSQLiteStore_RolePermissionsNaturalKey verifies the Phase A.5 junction
// schema: SetRolePermissions writes (role_id, perm_namespace_path, perm_name)
// rows, and ListRolePermissions returns full Permission records via JOIN.
func TestSQLiteStore_RolePermissionsNaturalKey(t *testing.T) {
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

	// Create role + perms.
	roleID := id.NewRoleID()
	now := time.Now()
	if err := s.CreateRole(ctx, &role.Role{
		ID: roleID, TenantID: "t1", Name: "Editor", Slug: "editor", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	for _, name := range []string{"document:read", "document:write"} {
		if err := s.CreatePermission(ctx, &permission.Permission{
			ID: id.NewPermissionID(), TenantID: "t1", Name: name,
			Resource: "document", Action: name[len("document:"):],
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreatePermission %s: %v", name, err)
		}
	}

	// Attach two permissions by ref.
	for _, name := range []string{"document:read", "document:write"} {
		if err := s.AttachPermission(ctx, roleID, permission.Ref{Name: name}); err != nil {
			t.Fatalf("AttachPermission %s: %v", name, err)
		}
	}

	// JOIN-based ListRolePermissions returns full records.
	got, err := s.ListRolePermissions(ctx, roleID)
	if err != nil {
		t.Fatalf("ListRolePermissions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 perms, got %d", len(got))
	}
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
		if p.Resource != "document" {
			t.Errorf("expected Resource=document, got %q", p.Resource)
		}
	}
	if !names["document:read"] || !names["document:write"] {
		t.Errorf("missing expected permission names: %v", names)
	}

	// Detach one, confirm the other remains.
	if err := s.DetachPermission(ctx, roleID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("DetachPermission: %v", err)
	}
	got, _ = s.ListRolePermissions(ctx, roleID)
	if len(got) != 1 || got[0].Name != "document:write" {
		t.Fatalf("after detach: got %d perms, want 1 (write)", len(got))
	}

	// SetRolePermissions replaces.
	if err := s.SetRolePermissions(ctx, roleID, []permission.Ref{{Name: "document:read"}}); err != nil {
		t.Fatalf("SetRolePermissions: %v", err)
	}
	got, _ = s.ListRolePermissions(ctx, roleID)
	if len(got) != 1 || got[0].Name != "document:read" {
		t.Fatalf("after set: got %d perms, want 1 (read)", len(got))
	}
}

// TestSQLiteStore_RoleParentSlugRoundTrip verifies that the optional
// ParentSlug field round-trips correctly (it's a *string which the wrapper
// must not interfere with).
func TestSQLiteStore_RoleParentSlugRoundTrip(t *testing.T) {
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

	parentID := id.NewRoleID()
	if err := s.CreateRole(ctx, &role.Role{
		ID: parentID, TenantID: "t1", Name: "Viewer", Slug: "viewer", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create parent: %v", err)
	}

	childID := id.NewRoleID()
	if err := s.CreateRole(ctx, &role.Role{
		ID: childID, TenantID: "t1", Name: "Editor", Slug: "editor", ParentSlug: "viewer", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create child: %v", err)
	}

	got, err := s.GetRole(ctx, childID)
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.ParentSlug != "viewer" {
		t.Errorf("parent_slug = %q, want viewer", got.ParentSlug)
	}
}
