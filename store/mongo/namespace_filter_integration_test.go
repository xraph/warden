//go:build integration

package mongo

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_NamespaceFilterContract runs the namespace-filter regression
// contract against a real MongoDB instance. It validates that the $in-based
// namespace filtering cascades correctly for ListRolesForSubject,
// ListRolesForSubjectOnResource, ListActivePolicies, CheckDirectRelation and
// ListRelationSubjects — the mongo equivalents of the postgres/sqlite fixes.
func TestMongo_NamespaceFilterContract(t *testing.T) {
	contract.RunNamespaceFilterContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}
