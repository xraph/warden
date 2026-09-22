//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_ExpiryContract runs the shared expiry-filtering contract
// against a real postgres instance.
func TestPostgres_ExpiryContract(t *testing.T) {
	contract.RunExpiryContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
