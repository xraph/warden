package role

import (
	"context"
	"sort"
	"strings"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/wardenerr"
)

// The checks below keep a role's grants honest. The REST API and the
// dashboard contract both call them, so the two refuse the same requests
// in the same words: a delete of a permission some role still grants, and
// a detach of a grant the role does not hold.

// grantPageSize is how many roles GrantingRoles reads per page.
const grantPageSize = 200

// GrantLister is the two store reads GrantingRoles needs.
type GrantLister interface {
	ListRoles(ctx context.Context, filter *ListFilter) ([]*Role, error)
	ListRolePermissionsForRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) (map[id.RoleID][]*permission.Permission, error)
}

// GrantingRoles returns every role in tenantID whose grants include pm,
// matched on (namespace, name), sorted by slug, then namespace, then ID.
//
// There is no store method for this direction, so it walks the tenant's
// roles a page at a time and checks each page's grants. It reads every page
// and never stops at a limit: CheckPermissionUngranted refuses a delete
// when this returns anyone, and a scan that gave up early would let the
// delete strip the grant from a role nobody was warned about.
func GrantingRoles(ctx context.Context, s GrantLister, tenantID string, pm *permission.Permission) ([]*Role, error) {
	out := []*Role{}
	for offset := 0; ; offset += grantPageSize {
		roles, err := s.ListRoles(ctx, &ListFilter{TenantID: tenantID, Limit: grantPageSize, Offset: offset})
		if err != nil {
			return nil, err
		}
		if len(roles) == 0 {
			break
		}
		ids := make([]id.RoleID, 0, len(roles))
		byID := make(map[id.RoleID]*Role, len(roles))
		for _, r := range roles {
			ids = append(ids, r.ID)
			byID[r.ID] = r
		}
		grants, err := s.ListRolePermissionsForRoles(ctx, tenantID, ids)
		if err != nil {
			return nil, err
		}
		for rid, held := range grants {
			for _, g := range held {
				if g != nil && g.Name == pm.Name && g.NamespacePath == pm.NamespacePath {
					if r, ok := byID[rid]; ok {
						out = append(out, r)
					}
					break
				}
			}
		}
		if len(roles) < grantPageSize {
			break
		}
	}
	// Ranging over the grants map is unordered, so sort before returning.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slug != out[j].Slug {
			return out[i].Slug < out[j].Slug
		}
		if out[i].NamespacePath != out[j].NamespacePath {
			return out[i].NamespacePath < out[j].NamespacePath
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

// PermissionGrantedError refuses deleting a permission that roles still
// grant. Every store's DeletePermission also removes the grants, so the
// delete would silently strip it from those roles. Roles holds their slugs
// in GrantingRoles order. It wraps nothing: the REST API answers it with
// 409 and the dashboard with CONFLICT.
type PermissionGrantedError struct {
	Permission string
	Roles      []string
}

func (e *PermissionGrantedError) Error() string {
	return e.Permission + " is still granted by " + strings.Join(e.Roles, ", ") +
		". Detach it from those roles first."
}

// CheckPermissionUngranted refuses, with a *PermissionGrantedError, the
// delete of pm while any role in tenantID grants it. A store failure is
// returned as is.
func CheckPermissionUngranted(ctx context.Context, s GrantLister, tenantID string, pm *permission.Permission) error {
	holders, err := GrantingRoles(ctx, s, tenantID, pm)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return nil
	}
	slugs := make([]string, 0, len(holders))
	for _, h := range holders {
		slugs = append(slugs, h.Slug)
	}
	return &PermissionGrantedError{Permission: pm.Name, Roles: slugs}
}

// GrantNotHeldError refuses detaching a grant the role does not hold. It
// wraps wardenerr.ErrNotFound, so the REST API answers it with 404 and the
// dashboard with NOT_FOUND.
type GrantNotHeldError struct {
	Role       string
	Permission string
}

func (e *GrantNotHeldError) Error() string {
	return e.Role + " does not grant " + e.Permission
}

func (e *GrantNotHeldError) Unwrap() error { return wardenerr.ErrNotFound }

// GrantReader is the one store read HeldGrant needs.
type GrantReader interface {
	ListRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error)
}

// HeldGrant returns the permission r grants under ref's exact (namespace,
// name) key, or a *GrantNotHeldError when it grants none. A detach checks
// this first because DetachPermission removes nothing and returns no error
// when the key does not match, so a detach naming the wrong namespace
// would report success while the grant survived. A store failure is
// returned as is.
func HeldGrant(ctx context.Context, s GrantReader, tenantID string, r *Role, ref permission.Ref) (*permission.Permission, error) {
	grants, err := s.ListRolePermissions(ctx, tenantID, r.ID)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if g != nil && g.Name == ref.Name && g.NamespacePath == ref.NamespacePath {
			return g, nil
		}
	}
	return nil, &GrantNotHeldError{Role: r.Name, Permission: ref.Name}
}
