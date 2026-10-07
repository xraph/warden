//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_ResourceTypeEmptyListsContract proves a resource type with nil
// relation and permission lists is stored in the NOT NULL jsonb columns of a
// real postgres instance.
func TestPostgres_ResourceTypeEmptyListsContract(t *testing.T) {
	contract.RunResourceTypeEmptyListsContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
