package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_RelationGetContract proves GetRelation reads a tuple back by ID
// in its own tenant and reports another tenant's ID as not found.
func TestMemory_RelationGetContract(t *testing.T) {
	contract.RunRelationGetContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
