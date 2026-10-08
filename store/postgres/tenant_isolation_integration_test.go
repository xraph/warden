//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_TenantIsolationContract runs the tenant-isolation contract
// against a real postgres instance. Only here do the DELETE cascades and the
// RowsAffected()==0 mapping get exercised against the real planner.
func TestPostgres_TenantIsolationContract(t *testing.T) {
	contract.RunTenantIsolationContract(t, newPostgresContractStore)
}

// TestPostgres_ActorFieldsContract runs the CreatedBy/UpdatedBy/GrantedBy
// round-trip contract against a real postgres instance.
func TestPostgres_ActorFieldsContract(t *testing.T) {
	contract.RunActorFieldsContract(t, newPostgresContractStore)
}

// TestEmptyTenantContract pins what a real postgres instance does with an
// empty TenantID.
func TestEmptyTenantContract(t *testing.T) {
	contract.RunEmptyTenantContract(t, newPostgresContractStore)
}

func newPostgresContractStore(t *testing.T) store.Store {
	s, cleanup := setupPostgres(t)
	t.Cleanup(cleanup)
	return s
}
