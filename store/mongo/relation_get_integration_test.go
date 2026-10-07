//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_RelationGetContract proves GetRelation on a real MongoDB
// instance.
func TestMongo_RelationGetContract(t *testing.T) {
	contract.RunRelationGetContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}

// TestMongo_RelationDeleteTupleContract proves a delete by composite key
// removes exactly the tuple it names, subject relation included, and
// nothing outside it.
func TestMongo_RelationDeleteTupleContract(t *testing.T) {
	contract.RunRelationDeleteTupleContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
