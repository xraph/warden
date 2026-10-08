//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_TenantMaintenanceContract proves the tenant-scoped purges on a
// real postgres instance. warden_check_logs refuses UPDATE but allows
// DELETE, so a tenant purge works there the same way PurgeCheckLogs does.
func TestPostgres_TenantMaintenanceContract(t *testing.T) {
	contract.RunTenantMaintenanceContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
