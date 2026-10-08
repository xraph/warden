//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_PolicyRenameUniquenessContract proves a policy rename onto a
// taken name is ErrDuplicatePolicy, not a raw duplicate key error, on a real
// MongoDB instance.
func TestMongo_PolicyRenameUniquenessContract(t *testing.T) {
	contract.RunPolicyRenameUniquenessContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
