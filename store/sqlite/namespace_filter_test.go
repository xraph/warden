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

// TestSQLite_NamespaceFilterContract runs the namespace-filter regression
// contract against an on-disk sqlite store. Before the fix, the
// `namespace_path IN (?)` queries bound the whole []string to a single
// placeholder and this test failed; it now guards against regression and
// runs under plain `go test` (no Docker).
func TestSQLite_NamespaceFilterContract(t *testing.T) {
	contract.RunNamespaceFilterContract(t, func(t *testing.T) (store.Store, func()) {
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
