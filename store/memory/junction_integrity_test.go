package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_JunctionIntegrityContract runs the shared role/permission
// junction-integrity contract against the in-memory store.
func TestMemory_JunctionIntegrityContract(t *testing.T) {
	contract.RunJunctionIntegrityContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
