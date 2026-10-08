package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden/role"
)

// RunEmptyTenantContract documents what a query with an empty TenantID
// returns, on whichever backend it runs against.
//
// This is not a test of desired behaviour. It is a record of actual
// behaviour, because the contract layer's tenant resolution refuses rather
// than passing an empty tenant through, and that refusal is only obviously
// correct while somebody remembers what empty does. If empty matches every
// row, this test says so in a place that cannot be forgotten.
//
// If the four backends disagree with each other, that disagreement is the
// finding. Do not weaken the assertion until it satisfies all four.
func RunEmptyTenantContract(t *testing.T, mk NewStore) {
	t.Run("ListRoles with an empty tenant", func(t *testing.T) {
		s := mk(t)
		ctx := context.Background()

		for _, tenant := range []string{"t1", "t2"} {
			r := &role.Role{TenantID: tenant, Name: "R", Slug: "r"}
			if err := s.CreateRole(ctx, r); err != nil {
				t.Fatalf("create role in %s: %v", tenant, err)
			}
		}

		got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: ""})
		if err != nil {
			t.Fatalf("ListRoles with empty tenant: %v", err)
		}

		// The behaviour this pins: an empty TenantID is not a filter, so
		// every tenant's rows come back. Two tenants were seeded and both
		// are returned. This is exactly why the dashboard contract layer
		// refuses an unresolvable tenant instead of passing one through.
		if len(got) != 2 {
			t.Fatalf("empty tenant returned %d roles across 2 tenants; "+
				"this backend filters differently from the others, which is "+
				"the finding rather than a reason to loosen this assertion", len(got))
		}
	})
}
