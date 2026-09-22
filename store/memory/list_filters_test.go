package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_ListFiltersContract runs the shared namespace/list-filter
// contract against the in-memory store.
func TestMemory_ListFiltersContract(t *testing.T) {
	contract.RunListFiltersContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
