//go:build integration

// MongoDB integration-test harness.
//
// setupMongo returns a fresh Store backed by a real MongoDB instance. By
// default a testcontainers-managed mongo:7 container is started lazily and
// shared across all tests in this package; each call gets a freshly-named
// database within that container (dropped on cleanup). Set
// WARDEN_TEST_MONGO_URI to use your own MongoDB instead.

package mongo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	tcmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/warden/store"
)

// mongoOnce caches the testcontainers-managed mongo so multiple tests share a
// single container. Each test opens its own database off this URI.
var (
	mongoOnce sync.Once
	mongoURI  string
	errMongo  error
)

// connURI returns a MongoDB connection URI. Resolution order:
//  1. WARDEN_TEST_MONGO_URI env var (skip container, use existing instance).
//  2. Lazily-created testcontainers-managed mongo:7.
func connURI(t *testing.T) string {
	t.Helper()
	if uri := os.Getenv("WARDEN_TEST_MONGO_URI"); uri != "" {
		return uri
	}
	mongoOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		c, err := tcmongo.Run(ctx, "mongo:7")
		if err != nil {
			errMongo = fmt.Errorf("start mongo container: %w", err)
			return
		}
		uri, err := c.ConnectionString(ctx)
		if err != nil {
			errMongo = fmt.Errorf("get mongo URI: %w", err)
			return
		}
		mongoURI = uri
	})
	if errMongo != nil {
		t.Skipf("mongo container unavailable: %v", errMongo)
	}
	return mongoURI
}

// setupMongo opens a fresh database and migrated Warden store. Returns the
// store and a cleanup function that drops the database.
func setupMongo(t *testing.T) (store.Store, func()) {
	t.Helper()
	uri := connURI(t)
	dbName := freshDBName(t)
	ctx := context.Background()

	drv := mongodriver.New()
	if err := drv.Open(ctx, uri, mongodriver.WithDatabase(dbName)); err != nil {
		t.Fatalf("open mongo: %v", err)
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
		_ = drv.Database().Drop(context.Background())
		_ = drv.Close()
	}
	return s, cleanup
}

// freshDBName returns a unique, mongo-safe database name.
func freshDBName(t *testing.T) string {
	t.Helper()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("warden_test_%s", hex.EncodeToString(rnd[:]))
}
