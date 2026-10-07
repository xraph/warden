//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_RelationGetContract proves GetRelation on a real postgres
// instance.
func TestPostgres_RelationGetContract(t *testing.T) {
	contract.RunRelationGetContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}

// TestPostgres_RelationDeleteTupleContract proves a delete by composite key
// removes every tuple the key matches and nothing outside it.
func TestPostgres_RelationDeleteTupleContract(t *testing.T) {
	contract.RunRelationDeleteTupleContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
