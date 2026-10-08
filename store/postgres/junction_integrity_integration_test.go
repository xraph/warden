//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_JunctionIntegrityContract runs the shared role/permission
// junction-integrity contract against a real postgres instance.
func TestPostgres_JunctionIntegrityContract(t *testing.T) {
	contract.RunJunctionIntegrityContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
