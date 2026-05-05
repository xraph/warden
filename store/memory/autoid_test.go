package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestAutoID exercises the shared store contract for auto-assigned IDs
// and timestamps against the memory backend. The contract package
// owns the assertions; this test just plumbs in a fresh memory.Store.
func TestAutoID(t *testing.T) {
	contract.RunAutoIDContract(t, func(t *testing.T) (store.Store, func()) {
		t.Helper()
		return New(), func() {}
	})
}
