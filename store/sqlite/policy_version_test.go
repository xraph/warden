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

// TestSQLite_PolicyVersionContract proves UpdatePolicyIfVersion is an atomic
// compare-and-write on an on-disk sqlite store.
//
// The racing-writers case sends 8 writes at once through grove's connection
// pool. Without a busy_timeout, sqlite answers every writer that finds the
// lock held with SQLITE_BUSY at once (see doc.go), which says nothing about
// the version guard. The DSN sets busy_timeout on every pooled connection,
// as doc.go recommends, so each writer waits its turn and then meets the
// guard.
func TestSQLite_PolicyVersionContract(t *testing.T) {
	contract.RunPolicyVersionContract(t, func(t *testing.T) (store.Store, func()) {
		dsn := "file:" + filepath.Join(t.TempDir(), "warden.db") + "?_pragma=busy_timeout(5000)"
		drv := sqlitedriver.New()
		if err := drv.Open(context.Background(), dsn); err != nil {
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
