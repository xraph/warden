package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_NamespaceFilterContract runs the namespace-filter regression
// contract against the in-memory store. The memory store iterates in Go and
// always satisfied this; it's included for parity so the contract is exercised
// without a database.
func TestMemory_NamespaceFilterContract(t *testing.T) {
	contract.RunNamespaceFilterContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
