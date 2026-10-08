package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_ExpiryContract runs the shared expiry-filtering contract
// against the in-memory store.
func TestMemory_ExpiryContract(t *testing.T) {
	contract.RunExpiryContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
