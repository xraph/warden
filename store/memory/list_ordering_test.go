package memory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
)

// TestListRoles_StablePagingAcrossPages guards against the map-iteration
// bug: ListRoles used to walk a Go map directly, so two calls with the same
// filter could return the 30 seeded roles in different orders. Offset
// paging over an unstable order can skip or repeat rows across pages.
//
// The fix sorts every List* result by (CreatedAt, ID) ascending before
// applying Offset/Limit, so three pages of 10 (Offset 0, 10, 20) always
// partition the 30 rows with no gaps and no repeats. The whole seed-and-page
// cycle runs 20 times to make a flake from map-order nondeterminism
// vanishingly unlikely to slip through.
func TestListRoles_StablePagingAcrossPages(t *testing.T) {
	ctx := context.Background()
	const tenantID = "list-ordering-t1"
	const total = 30
	const pageSize = 10

	for iter := 0; iter < 20; iter++ {
		s := New()
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		want := make(map[string]struct{}, total)
		for i := 0; i < total; i++ {
			r := &role.Role{
				ID:        id.NewRoleID(),
				TenantID:  tenantID,
				Name:      fmt.Sprintf("role-%02d", i),
				Slug:      fmt.Sprintf("role-%02d", i),
				CreatedAt: base.Add(time.Duration(i) * time.Minute),
			}
			if err := s.CreateRole(ctx, r); err != nil {
				t.Fatalf("iter %d: seed role %d: %v", iter, i, err)
			}
			want[r.ID.String()] = struct{}{}
		}

		got := make(map[string]struct{}, total)
		for _, offset := range []int{0, 10, 20} {
			page, err := s.ListRoles(ctx, &role.ListFilter{TenantID: tenantID, Limit: pageSize, Offset: offset})
			if err != nil {
				t.Fatalf("iter %d: ListRoles offset %d: %v", iter, offset, err)
			}
			if len(page) != pageSize {
				t.Fatalf("iter %d: ListRoles offset %d: want %d rows, got %d", iter, offset, pageSize, len(page))
			}
			for _, r := range page {
				key := r.ID.String()
				if _, dup := got[key]; dup {
					t.Fatalf("iter %d: role %s returned more than once across pages", iter, key)
				}
				got[key] = struct{}{}
			}
		}

		if len(got) != total {
			t.Fatalf("iter %d: union of pages has %d roles, want %d", iter, len(got), total)
		}
		for key := range want {
			if _, ok := got[key]; !ok {
				t.Fatalf("iter %d: role %s missing from the paged union", iter, key)
			}
		}
	}
}
