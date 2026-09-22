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

// stripPage returns a copy of the filter with Limit and Offset cleared, so the
// wrapped store hands back every matching row for pageOf to order.
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

func (c *cappingStore) ListRoles(ctx context.Context, f *role.ListFilter) ([]*role.Role, error) {
	limit, offset := pageArgs(f, func(x *role.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := c.Store.ListRoles(ctx, stripPage(f, func(x *role.ListFilter) (*int, *int) { return &x.Limit, &x.Offset }))
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(r *role.Role) (time.Time, string) { return r.CreatedAt, r.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListPermissions(ctx context.Context, f *permission.ListFilter) ([]*permission.Permission, error) {
	limit, offset := pageArgs(f, func(x *permission.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := c.Store.ListPermissions(ctx, stripPage(f, func(x *permission.ListFilter) (*int, *int) { return &x.Limit, &x.Offset }))
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(p *permission.Permission) (time.Time, string) { return p.CreatedAt, p.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListPolicies(ctx context.Context, f *policy.ListFilter) ([]*policy.Policy, error) {
	limit, offset := pageArgs(f, func(x *policy.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := c.Store.ListPolicies(ctx, stripPage(f, func(x *policy.ListFilter) (*int, *int) { return &x.Limit, &x.Offset }))
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(p *policy.Policy) (time.Time, string) { return p.CreatedAt, p.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListResourceTypes(ctx context.Context, f *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	limit, offset := pageArgs(f, func(x *resourcetype.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := c.Store.ListResourceTypes(ctx, stripPage(f, func(x *resourcetype.ListFilter) (*int, *int) { return &x.Limit, &x.Offset }))
	if err != nil {
		return nil, err
	}
	return pageOf(rows, func(rt *resourcetype.ResourceType) (time.Time, string) { return rt.CreatedAt, rt.ID.String() }, limit, offset), nil
}

func (c *cappingStore) ListRelations(ctx context.Context, f *relation.ListFilter) ([]*relation.Tuple, error) {
	limit, offset := pageArgs(f, func(x *relation.ListFilter) (int, int) { return x.Limit, x.Offset })
	rows, err := c.Store.ListRelations(ctx, stripPage(f, func(x *relation.ListFilter) (*int, *int) { return &x.Limit, &x.Offset }))
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
