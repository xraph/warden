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

// TestSQLite_ExpiryContract runs the shared expiry-filtering contract
// against an on-disk sqlite store, exercising the real
// `expires_at IS NULL OR expires_at > ?` predicate bound through sqliteTime.
func TestSQLite_ExpiryContract(t *testing.T) {
	contract.RunExpiryContract(t, func(t *testing.T) (store.Store, func()) {
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
		return s, func() { _ = drv.Close() }
	})
}
