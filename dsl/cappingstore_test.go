package dsl

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// cappingStore wraps the memory store so its List* methods behave like the
// Postgres and SQLite backends: rows come back ordered by creation time and
// truncated at storeDefaultLimit when the caller leaves Limit at zero.
//
// The memory backend does neither: it returns every row, in Go map order,
// which is randomised per call. Testing pagination against it would both hide
// the truncation these tests exist to catch and make offset paging
// meaningless. The ordering here is the tiebroken order a backend needs for
// offset paging to be sound, so a green test says the DSL layer is correct
// given a correct backend.
type cappingStore struct {
	*memory.Store
}

// pageOf orders rows by (created_at, id) and applies the limit and offset the
// caller asked for, defaulting the limit the way the SQL backends do.
func pageOf[T any](rows []T, key func(T) (time.Time, string), limit, offset int) []T {
	slices.SortFunc(rows, func(a, b T) int {
		at, aid := key(a)
		bt, bid := key(b)
		if c := at.Compare(bt); c != 0 {
			return c
		}
		return strings.Compare(aid, bid)
	})
	if limit <= 0 {
		limit = storeDefaultLimit
	}
	if offset >= len(rows) {
		return nil
	}
	rows = rows[offset:]
	if limit < len(rows) {
		rows = rows[:limit]
	}
	return rows
}

// stripPage returns a copy of the filter with Limit and Offset cleared.
func stripPage[F any](f *F, fields func(*F) (*int, *int)) *F {
	if f == nil {
		var zero F
		f = &zero
	}
	c := *f
	l, o := fields(&c)
	*l, *o = 0, 0
	return &c
}

// fetchAll fetches the full result set from the wrapped store in a single
// call, with an explicit Limit (maxCollectedRows, the same ceiling
// collectPages itself enforces) so the memory store's own default-limit
// cap (applyPagination now truncates at 1000 when Limit is left at zero,
// matching the SQL backends) never bites.
//
// A single call, not several with increasing Offset: the memory backend
// enumerates in Go map order, which the language randomises fresh on
// every separate range over the map. Two calls a moment apart can walk
// the same rows in two different orders, so an Offset chosen against one
// call's ordering does not name the same rows in the next call, and
// paging across multiple calls would return rows out of sequence,
// duplicated, or skipped. One call sees one consistent snapshot; pageOf
// then imposes the one deterministic sort cappingStore promises, and
// slices that sorted snapshot exactly like a real ordered backend would.
func fetchAll[F any, T any](ctx context.Context, list func(context.Context, *F) ([]T, error), f *F, fields func(*F) (*int, *int)) ([]T, error) {
	base := stripPage(f, fields)
	limitPtr, offsetPtr := fields(base)
	*limitPtr, *offsetPtr = maxCollectedRows, 0
	return list(ctx, base)
}

func (c *cappingStore) ListRoles(ctx context.Context, f *role.ListFilter) ([]*role.Role, error) {
	limit, offset := pageArgs(f, func(x *role.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := fetchAll(ctx, c.Store.ListRoles, f, func(x *role.ListFilter) (*int, *int) { return &x.Limit, &x.Offset })
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(r *role.Role) (time.Time, string) { return r.CreatedAt, r.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListPermissions(ctx context.Context, f *permission.ListFilter) ([]*permission.Permission, error) {
	limit, offset := pageArgs(f, func(x *permission.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := fetchAll(ctx, c.Store.ListPermissions, f, func(x *permission.ListFilter) (*int, *int) { return &x.Limit, &x.Offset })
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(p *permission.Permission) (time.Time, string) { return p.CreatedAt, p.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListPolicies(ctx context.Context, f *policy.ListFilter) ([]*policy.Policy, error) {
	limit, offset := pageArgs(f, func(x *policy.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := fetchAll(ctx, c.Store.ListPolicies, f, func(x *policy.ListFilter) (*int, *int) { return &x.Limit, &x.Offset })
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(p *policy.Policy) (time.Time, string) { return p.CreatedAt, p.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListResourceTypes(ctx context.Context, f *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	limit, offset := pageArgs(f, func(x *resourcetype.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := fetchAll(ctx, c.Store.ListResourceTypes, f, func(x *resourcetype.ListFilter) (*int, *int) { return &x.Limit, &x.Offset })
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(rt *resourcetype.ResourceType) (time.Time, string) { return rt.CreatedAt, rt.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListRelations(ctx context.Context, f *relation.ListFilter) ([]*relation.Tuple, error) {
	limit, offset := pageArgs(f, func(x *relation.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := fetchAll(ctx, c.Store.ListRelations, f, func(x *relation.ListFilter) (*int, *int) { return &x.Limit, &x.Offset })
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(t *relation.Tuple) (time.Time, string) { return t.CreatedAt, t.ID.String() }, limit, offset), nil
}

func pageArgs[F any](f *F, get func(*F) (int, int)) (limit, offset int) {
	if f == nil {
		return 0, 0
	}
	return get(f)
}
