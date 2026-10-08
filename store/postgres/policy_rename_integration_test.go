//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_PolicyRenameUniquenessContract proves a policy rename onto a
// taken name is ErrDuplicatePolicy, not a raw unique violation, on a real
// postgres instance.
func TestPostgres_PolicyRenameUniquenessContract(t *testing.T) {
	contract.RunPolicyRenameUniquenessContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
