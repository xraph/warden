//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_PolicyVersionContract proves UpdatePolicyIfVersion on a real
// MongoDB instance: it writes on a matching version, refuses a stale one
// without writing, tells not-found from stale, and lets exactly one of
// several racing writers win.
func TestMongo_PolicyVersionContract(t *testing.T) {
	contract.RunPolicyVersionContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
