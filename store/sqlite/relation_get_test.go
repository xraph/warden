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

// TestSQLite_RelationGetContract proves GetRelation on an on-disk sqlite
// store, including the metadata JSON round trip.
func TestSQLite_RelationGetContract(t *testing.T) {
	contract.RunRelationGetContract(t, func(t *testing.T) (store.Store, func()) {
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

// TestSQLite_RelationDeleteTupleContract proves a delete by composite key
// removes exactly the tuple it names, subject relation included, and
// nothing outside it.
func TestSQLite_RelationDeleteTupleContract(t *testing.T) {
	contract.RunRelationDeleteTupleContract(t, func(t *testing.T) (store.Store, func()) {
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
