// Package cli holds shared helpers for the warden CLI binaries.
package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Side-effect imports register migration executors for each driver so
	// store.Migrate() can find them.
	_ "github.com/xraph/grove/drivers/pgdriver/pgmigrate"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/memory"
	pgstore "github.com/xraph/warden/store/postgres"
	sqlitestore "github.com/xraph/warden/store/sqlite"
)

// OpenStore opens a warden Store from a DSN string.
//
// Supported DSN forms:
//
//	memory:                              — in-memory (testing only; data is lost on exit)
//	sqlite:<path>                        — SQLite file
//	postgres://user:pass@host:port/db    — Postgres connection URL
//	postgresql://user:pass@host:port/db  — same as above
func OpenStore(ctx context.Context, dsn string) (store.Store, func() error, error) {
	switch {
	case dsn == "memory:" || dsn == "memory":
		s := memory.New()
		return s, func() error { return nil }, nil

	case strings.HasPrefix(dsn, "sqlite:"):
		path := strings.TrimPrefix(dsn, "sqlite:")
		path = strings.TrimPrefix(path, "//")
		if path == "" {
			return nil, nil, fmt.Errorf("warden cli: empty sqlite path in DSN %q", dsn)
		}
		drv := sqlitedriver.New()
		if err := drv.Open(ctx, path); err != nil {
			return nil, nil, fmt.Errorf("warden cli: open sqlite %q: %w", path, err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			_ = drv.Close()
			return nil, nil, fmt.Errorf("warden cli: grove open sqlite: %w", err)
		}
		s := sqlitestore.New(db)
		return s, db.Close, nil

	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		drv := pgdriver.New()
		if err := drv.Open(ctx, dsn); err != nil {
			return nil, nil, fmt.Errorf("warden cli: open postgres: %w", err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			_ = drv.Close()
			return nil, nil, fmt.Errorf("warden cli: grove open postgres: %w", err)
		}
		s := pgstore.New(db)
		return s, db.Close, nil

	default:
		return nil, nil, fmt.Errorf("warden cli: unsupported DSN %q (use memory:, sqlite:<path>, or postgres://...)", dsn)
	}
}

// MaybeMigrate runs the store's auto-migrations unless skip is true.
func MaybeMigrate(ctx context.Context, s store.Store, skip bool) error {
	if skip {
		return nil
	}
	return s.Migrate(ctx)
}
