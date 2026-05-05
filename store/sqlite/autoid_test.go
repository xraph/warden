package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Side-effect import: register the SQLite migration executor.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestAutoID exercises the shared store contract for auto-assigned IDs
// and timestamps against the SQLite backend. Each sub-test gets a
// fresh in-tree DB file so writes don't leak between cases.
func TestAutoID(t *testing.T) {
	contract.RunAutoIDContract(t, func(t *testing.T) (store.Store, func()) {
		t.Helper()
		ctx := context.Background()
		dbPath := filepath.Join(t.TempDir(), "warden.db")

		drv := sqlitedriver.New()
		if err := drv.Open(ctx, dbPath); err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			_ = drv.Close()
			t.Fatalf("grove open: %v", err)
		}
		s := New(db)
		if err := s.Migrate(ctx); err != nil {
			_ = drv.Close()
			t.Fatalf("migrate: %v", err)
		}
		cleanup := func() {
			_ = drv.Close()
		}
		return s, cleanup
	})
}
