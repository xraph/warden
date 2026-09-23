//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_TenantIsolationContract runs the tenant-isolation contract
// against a real MongoDB instance, covering the bson filter form of the
// tenant predicate and the MatchedCount/DeletedCount not-found mapping.
func TestMongo_TenantIsolationContract(t *testing.T) {
	contract.RunTenantIsolationContract(t, newMongoContractStore)
}

// TestMongo_ActorFieldsContract runs the CreatedBy/UpdatedBy/GrantedBy
// round-trip contract against a real MongoDB instance.
func TestMongo_ActorFieldsContract(t *testing.T) {
	contract.RunActorFieldsContract(t, newMongoContractStore)
}

// TestEmptyTenantContract pins what a real MongoDB instance does with an
// empty TenantID.
func TestEmptyTenantContract(t *testing.T) {
	contract.RunEmptyTenantContract(t, newMongoContractStore)
}

func newMongoContractStore(t *testing.T) store.Store {
	s, cleanup := setupMongo(t)
	t.Cleanup(cleanup)
	return s
}
