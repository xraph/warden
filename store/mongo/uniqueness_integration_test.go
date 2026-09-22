//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_UniquenessContract runs the shared uniqueness contract against a
// real MongoDB instance: it proves the namespace_unique migration widened
// every entity's unique index to (tenant_id, namespace_path, slug|name).
// The same slug/name is rejected within a scope, but allowed across
// namespaces and across tenants.
func TestMongo_UniquenessContract(t *testing.T) {
	contract.RunUniquenessContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
