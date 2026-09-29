//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_ListFiltersContract runs the shared namespace/list-filter
// contract against a real MongoDB instance. Mongo had no runner for this
// contract, which is how it kept two divergences the other backends had
// already fixed: no default cap on an unlimited List* call, and a sort on
// created_at with no tiebreaker to make it a total order.
func TestMongo_ListFiltersContract(t *testing.T) {
	contract.RunListFiltersContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
