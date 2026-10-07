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
