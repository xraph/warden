//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_NamespaceFilterContract runs the namespace-filter regression
// contract against a real postgres instance. It validates the WhereArray
// ("namespace_path = ANY ($N)") path end-to-end, including pgx encoding the
// []string as a text[] — the in-process sqlite test can't exercise that.
func TestPostgres_NamespaceFilterContract(t *testing.T) {
	contract.RunNamespaceFilterContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
