//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_ResourceTypeEmptyListsContract proves a resource type with nil
// relation and permission lists round-trips through a real MongoDB instance.
func TestMongo_ResourceTypeEmptyListsContract(t *testing.T) {
	contract.RunResourceTypeEmptyListsContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
