// Package cli holds shared helpers for the warden CLI binaries.
package cli

import (
	"context"
	"fmt"
	"net/url"
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

// redactDSN returns a copy of dsn safe to put in a log line or an error
// message. A postgres DSN carries its password in the userinfo component
// (postgres://user:pass@host/db); OpenStore's own error strings must never
// echo that back verbatim, since these errors end up on stderr, in CI logs,
// and sometimes in bug reports pasted into an issue.
//
// dsn forms without credentials (memory:, sqlite:<path>) pass through
// url.Parse without a User component and come back unchanged. A dsn that
// doesn't parse as a URL at all is treated as unsafe to print and replaced
// with a fixed placeholder, since we can't rule out a password living
// somewhere in an unparseable string.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<redacted DSN>"
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	return u.Redacted()
}

// OpenStore opens a warden Store from a DSN string.
//
// Supported DSN forms:
//
//	memory:                              in-memory (testing only; data is lost on exit)
//	sqlite:<path>                        SQLite file
//	postgres://user:pass@host:port/db    Postgres connection URL
//	postgresql://user:pass@host:port/db  same as above
func OpenStore(ctx context.Context, dsn string) (store.Store, func() error, error) {
	switch {
	case dsn == "memory:" || dsn == "memory":
		s := memory.New()
		return s, func() error { return nil }, nil

	case strings.HasPrefix(dsn, "sqlite:"):
		path := strings.TrimPrefix(dsn, "sqlite:")
		path = strings.TrimPrefix(path, "//")
		if path == "" {
			return nil, nil, fmt.Errorf("warden cli: empty sqlite path in DSN %q", redactDSN(dsn))
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
			return nil, nil, fmt.Errorf("warden cli: open postgres %s: %w", redactDSN(dsn), err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			_ = drv.Close()
			return nil, nil, fmt.Errorf("warden cli: grove open postgres %s: %w", redactDSN(dsn), err)
		}
		s := pgstore.New(db)
		return s, db.Close, nil

	default:
		return nil, nil, fmt.Errorf("warden cli: unsupported DSN %q (use memory:, sqlite:<path>, or postgres://...)", redactDSN(dsn))
	}
}

// MaybeMigrate runs the store's auto-migrations unless skip is true.
func MaybeMigrate(ctx context.Context, s store.Store, skip bool) error {
	if skip {
		return nil
	}
	return s.Migrate(ctx)
}
