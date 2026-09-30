//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_PolicyRoundTripContract proves a fully populated policy
// round-trips through a real MongoDB instance.
func TestMongo_PolicyRoundTripContract(t *testing.T) {
	contract.RunPolicyRoundTripContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
