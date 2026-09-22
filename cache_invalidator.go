package warden

import (
	"context"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
)

// cacheInvalidator is an internal plugin the engine registers automatically
// whenever a Cache is configured (WithCache, or Config.CacheTTL > 0). It
// keeps cached Check results from outliving the data that produced them.
//
// Hooks that carry the mutated entity (Created/Updated, and the assignment
// hooks) invalidate precisely: by tenant, or by subject for a role
// assignment change. Hooks that only carry a bare ID with no tenant context
// (every *Deleted hook, plus permission attach/detach) cannot target a
// tenant, so they fall back to a full Clear. A stale cache entry is the
// exact bug this hardening pass exists to close, so an occasional full
// flush on a less-common delete path is the right trade against that.
type cacheInvalidator struct {
	cache Cache
}

func newCacheInvalidator(c Cache) *cacheInvalidator { return &cacheInvalidator{cache: c} }

func (c *cacheInvalidator) Name() string { return "warden-cache-invalidator" }

func (c *cacheInvalidator) OnRoleCreated(ctx context.Context, r *role.Role) error {
	c.cache.InvalidateTenant(ctx, r.TenantID)
	return nil
}

func (c *cacheInvalidator) OnRoleUpdated(ctx context.Context, r *role.Role) error {
	c.cache.InvalidateTenant(ctx, r.TenantID)
	return nil
}

func (c *cacheInvalidator) OnRoleDeleted(ctx context.Context, _ id.RoleID) error {
	c.cache.Clear(ctx)
	return nil
}

func (c *cacheInvalidator) OnPermissionCreated(ctx context.Context, p *permission.Permission) error {
	c.cache.InvalidateTenant(ctx, p.TenantID)
	return nil
}

func (c *cacheInvalidator) OnPermissionDeleted(ctx context.Context, _ id.PermissionID) error {
	c.cache.Clear(ctx)
	return nil
}

func (c *cacheInvalidator) OnPermissionAttached(ctx context.Context, _ id.RoleID, _ id.PermissionID) error {
	c.cache.Clear(ctx)
	return nil
}

func (c *cacheInvalidator) OnPermissionDetached(ctx context.Context, _ id.RoleID, _ id.PermissionID) error {
	c.cache.Clear(ctx)
	return nil
}

func (c *cacheInvalidator) OnRoleAssigned(ctx context.Context, a *assignment.Assignment) error {
	c.cache.InvalidateSubject(ctx, a.TenantID, SubjectKind(a.SubjectKind), a.SubjectID)
	return nil
}

func (c *cacheInvalidator) OnRoleUnassigned(ctx context.Context, a *assignment.Assignment) error {
	c.cache.InvalidateSubject(ctx, a.TenantID, SubjectKind(a.SubjectKind), a.SubjectID)
	return nil
}

func (c *cacheInvalidator) OnRelationWritten(ctx context.Context, t *relation.Tuple) error {
	c.cache.InvalidateTenant(ctx, t.TenantID)
	return nil
}

func (c *cacheInvalidator) OnRelationDeleted(ctx context.Context, _ id.RelationID) error {
	c.cache.Clear(ctx)
	return nil
}

func (c *cacheInvalidator) OnPolicyCreated(ctx context.Context, p *policy.Policy) error {
	c.cache.InvalidateTenant(ctx, p.TenantID)
	return nil
}

func (c *cacheInvalidator) OnPolicyUpdated(ctx context.Context, p *policy.Policy) error {
	c.cache.InvalidateTenant(ctx, p.TenantID)
	return nil
}

func (c *cacheInvalidator) OnPolicyDeleted(ctx context.Context, _ id.PolicyID) error {
	c.cache.Clear(ctx)
	return nil
}

// OnAudit invalidates the tenant scope for every audited mutation,
// including ones no typed hook above covers (resourcetype.*,
// declarative.applied, ...).
func (c *cacheInvalidator) OnAudit(ctx context.Context, ev plugin.Event) error {
	c.cache.InvalidateTenant(ctx, ev.TenantID)
	return nil
}

// compile-time interface checks.
var (
	_ plugin.Plugin             = (*cacheInvalidator)(nil)
	_ plugin.RoleCreated        = (*cacheInvalidator)(nil)
	_ plugin.RoleUpdated        = (*cacheInvalidator)(nil)
	_ plugin.RoleDeleted        = (*cacheInvalidator)(nil)
	_ plugin.PermissionCreated  = (*cacheInvalidator)(nil)
	_ plugin.PermissionDeleted  = (*cacheInvalidator)(nil)
	_ plugin.PermissionAttached = (*cacheInvalidator)(nil)
	_ plugin.PermissionDetached = (*cacheInvalidator)(nil)
	_ plugin.RoleAssigned       = (*cacheInvalidator)(nil)
	_ plugin.RoleUnassigned     = (*cacheInvalidator)(nil)
	_ plugin.RelationWritten    = (*cacheInvalidator)(nil)
	_ plugin.RelationDeleted    = (*cacheInvalidator)(nil)
	_ plugin.PolicyCreated      = (*cacheInvalidator)(nil)
	_ plugin.PolicyUpdated      = (*cacheInvalidator)(nil)
	_ plugin.PolicyDeleted      = (*cacheInvalidator)(nil)
	_ plugin.Audit              = (*cacheInvalidator)(nil)
)
