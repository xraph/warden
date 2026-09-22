package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestSQLite_TenantIsolationContract runs the tenant-isolation contract
// against an on-disk sqlite store, so the tenant predicate is exercised as
// real SQL. It needs no Docker and runs under plain `go test`.
func TestSQLite_TenantIsolationContract(t *testing.T) {
	contract.RunTenantIsolationContract(t, func(t *testing.T) store.Store {
		dbPath := filepath.Join(t.TempDir(), "warden.db")
		drv := sqlitedriver.New()
		if err := drv.Open(context.Background(), dbPath); err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			_ = drv.Close()
			t.Fatalf("grove open: %v", err)
		}
		s := New(db)
		if err := s.Migrate(context.Background()); err != nil {
			_ = drv.Close()
			t.Fatalf("migrate: %v", err)
		}
		t.Cleanup(func() { _ = drv.Close() })
		return s
	})
}
