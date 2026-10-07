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
