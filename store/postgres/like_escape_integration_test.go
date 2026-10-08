//go:build integration

package postgres

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestPostgres_LikeEscapeContract runs the shared LIKE-escaping contract
// against a real postgres instance.
func TestPostgres_LikeEscapeContract(t *testing.T) {
	contract.RunLikeEscapeContract(t, func(t *testing.T) (store.Store, func()) {
		return setupPostgres(t)
	})
}
