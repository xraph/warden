//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_TenantMaintenanceContract proves the tenant-scoped purges on a
// real MongoDB instance.
func TestMongo_TenantMaintenanceContract(t *testing.T) {
	contract.RunTenantMaintenanceContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
