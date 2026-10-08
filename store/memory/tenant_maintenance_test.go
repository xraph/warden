package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_TenantMaintenanceContract proves the tenant-scoped purges
// remove one tenant's expired assignments and old check log entries and
// leave every other tenant's rows alone.
func TestMemory_TenantMaintenanceContract(t *testing.T) {
	contract.RunTenantMaintenanceContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
