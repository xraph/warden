//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_PolicyVersionContract proves UpdatePolicyIfVersion on a real
// postgres instance: it writes on a matching version, refuses a stale one
// without writing, tells not-found from stale, and lets exactly one of
// several racing writers win.
func TestPostgres_PolicyVersionContract(t *testing.T) {
	contract.RunPolicyVersionContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
