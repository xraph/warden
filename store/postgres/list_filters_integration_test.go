//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_ListFiltersContract runs the shared namespace/list-filter
// contract against a real postgres instance.
func TestPostgres_ListFiltersContract(t *testing.T) {
	contract.RunListFiltersContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
