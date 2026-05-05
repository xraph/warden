//go:build integration

// Postgres integration-test harness.
//
// setupPostgres returns a fresh Store backed by a real postgres
// instance. By default a testcontainers-managed postgres:16-alpine
// container is started lazily and shared across all tests in this
// package; each call gets a freshly-created database within that
// container. Set WARDEN_TEST_DSN to use your own postgres instead
// (faster local iteration, single-DSN sharing across packages).

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"

	// Side-effect import: register the postgres migration executor.
	_ "github.com/xraph/grove/drivers/pgdriver/pgmigrate"

	"github.com/xraph/warden/store"
)

// containerOnce caches the testcontainers-managed postgres so multiple
// tests share a single container. The DSN is the *admin* DSN — each
// test creates its own database off this connection.
var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

// adminDSN returns the connection string to a postgres instance with
// permission to create databases. Resolution order:
//  1. WARDEN_TEST_DSN env var (skip container, use existing DB).
//  2. Lazily-created testcontainers-managed postgres:16-alpine.
func adminDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("WARDEN_TEST_DSN"); dsn != "" {
		return dsn
	}
	containerOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
			tcpostgres.WithDatabase("warden_admin"),
			tcpostgres.WithUsername("warden"),
			tcpostgres.WithPassword("warden"),
			testcontainers.WithWaitStrategyAndDeadline(60*time.Second),
		)
		if err != nil {
			containerErr = fmt.Errorf("start postgres container: %w", err)
			return
		}
		dsn, err := c.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			containerErr = fmt.Errorf("get DSN: %w", err)
			return
		}
		containerDSN = dsn
	})
	if containerErr != nil {
		t.Skipf("postgres container unavailable: %v", containerErr)
	}
	return containerDSN
}

// setupPostgres opens a fresh database and migrated Warden store.
// Returns the store and a cleanup function (drops the database).
func setupPostgres(t *testing.T) (store.Store, func()) {
	t.Helper()
	admin := adminDSN(t)

	// Create a unique database for this test.
	dbName := freshDBName(t)
	ctx := context.Background()
	if err := createDatabase(ctx, admin, dbName); err != nil {
		t.Fatalf("create test database: %v", err)
	}

	dsn := replaceDBName(admin, dbName)
	drv := pgdriver.New()
	if err := drv.Open(ctx, dsn); err != nil {
		t.Fatalf("open postgres: %v", err)
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
		_ = dropDatabase(admin, dbName)
	}
	return s, cleanup
}

// freshDBName returns a unique, postgres-safe database name derived from
// the test name plus 8 random hex chars. Sanitized to lowercase letters,
// digits, and underscores only.
func freshDBName(t *testing.T) string {
	t.Helper()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("warden_test_%s", hex.EncodeToString(rnd[:]))
}

// createDatabase opens a single connection to the admin DSN and runs
// CREATE DATABASE. Uses pgx directly (not grove) because CREATE DATABASE
// can't run inside a pooled transaction.
func createDatabase(ctx context.Context, adminDSN, name string) error {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("admin connect: %w", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		return fmt.Errorf("CREATE DATABASE %s: %w", name, err)
	}
	return nil
}

// dropDatabase opens a single connection to the admin DSN and runs
// DROP DATABASE. Best-effort; failures are ignored at the call site.
func dropDatabase(adminDSN, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	return err
}

// replaceDBName swaps the database name in a postgres DSN. Handles URL
// form (postgres://user:pw@host:port/db?...) by replacing the last path
// segment before any query string.
func replaceDBName(dsn, dbName string) string {
	for i := len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '/' {
			end := len(dsn)
			for j := i + 1; j < len(dsn); j++ {
				if dsn[j] == '?' {
					end = j
					break
				}
			}
			return dsn[:i+1] + dbName + dsn[end:]
		}
	}
	return dsn
}
