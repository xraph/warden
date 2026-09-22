package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_TenantIsolationContract runs the tenant-isolation contract
// against the in-memory store. The memory store compares TenantID in Go
// rather than in SQL, so this is the fastest signal that the contract holds.
func TestMemory_TenantIsolationContract(t *testing.T) {
	contract.RunTenantIsolationContract(t, func(_ *testing.T) store.Store {
		return New()
	})
}
