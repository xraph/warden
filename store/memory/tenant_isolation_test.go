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

// TestMemory_ActorFieldsContract runs the CreatedBy/UpdatedBy/GrantedBy
// round-trip contract against the in-memory store.
func TestMemory_ActorFieldsContract(t *testing.T) {
	contract.RunActorFieldsContract(t, func(_ *testing.T) store.Store {
		return New()
	})
}

// TestEmptyTenantContract pins what the in-memory store does with an empty
// TenantID.
func TestEmptyTenantContract(t *testing.T) {
	contract.RunEmptyTenantContract(t, func(_ *testing.T) store.Store {
		return New()
	})
}
