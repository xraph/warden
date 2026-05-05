//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_Uniqueness runs the namespace-uniqueness contract against
// a real postgres instance. Verifies that the new UNIQUE constraints
// from migration 20260201000001 are correctly mapped to the typed
// ErrDuplicate* sentinels via isUniqueViolation.
func TestPostgres_Uniqueness(t *testing.T) {
	contract.RunUniquenessContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
