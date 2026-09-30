//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_PolicyRoundTripContract proves a fully populated policy
// round-trips through the jsonb columns of a real postgres instance.
func TestPostgres_PolicyRoundTripContract(t *testing.T) {
	contract.RunPolicyRoundTripContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
