package keysmithbridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
)

// pageSize bounds one read when unassign walks a key's assignments.
const pageSize = 500

// Bridge implements Keysmith's warden_hook WardenBridge on top of a Warden
// engine. Build one with New. It holds no state beyond the engine, so one
// value is safe to share across goroutines.
type Bridge struct {
	eng   *warden.Engine
	actor warden.Actor
}

// Option customises a Bridge.
type Option func(*Bridge)

// WithActor sets who the bridge's writes are attributed to when the context
// carries no actor of its own. The default is a service actor named
// "keysmith". The actor's ID is stored as the assignment's GrantedBy.
func WithActor(a warden.Actor) Option {
	return func(b *Bridge) { b.actor = a }
}

// New returns a Bridge that reads and writes through eng's store.
func New(eng *warden.Engine, opts ...Option) *Bridge {
	b := &Bridge{
		eng:   eng,
		actor: warden.Actor{Kind: "service", ID: "keysmith", Via: "keysmithbridge"},
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// AssignRoleToAPIKey gives the API key keyID the role with slug roleSlug, in
// the tenant's root namespace. The role must exist: a missing one is an error
// that names the slug. Assigning a role the key already holds is a no-op. A
// role with a member cap refuses a new key once it is full, as it would for
// any other subject.
func (b *Bridge) AssignRoleToAPIKey(ctx context.Context, tenantID, keyID, roleSlug string) error {
	if err := b.ready(tenantID); err != nil {
		return err
	}
	if keyID == "" {
		return errors.New("keysmithbridge: key ID is required")
	}
	if roleSlug == "" {
		return errors.New("keysmithbridge: role slug is required")
	}

	st := b.eng.Store()
	r, err := st.GetRoleBySlug(ctx, tenantID, "", roleSlug)
	if err != nil {
		if errors.Is(err, warden.ErrNotFound) {
			return fmt.Errorf("keysmithbridge: role %q not found in tenant %q: %w", roleSlug, tenantID, err)
		}
		return fmt.Errorf("keysmithbridge: look up role %q: %w", roleSlug, err)
	}

	now := time.Now().UTC()
	held, err := b.findLive(ctx, tenantID, keyID, r.ID, now)
	if err != nil {
		return err
	}
	if held {
		return nil
	}

	if err := assignment.CheckMemberCap(ctx, st, tenantID, r.ID, r.Name, r.MaxMembers,
		string(warden.SubjectAPIKey), keyID, now); err != nil {
		return fmt.Errorf("keysmithbridge: assign role %q to key %q: %w", roleSlug, keyID, err)
	}

	actor := b.actorFor(ctx)
	a := &assignment.Assignment{
		ID:          id.NewAssignmentID(),
		TenantID:    tenantID,
		RoleID:      r.ID,
		SubjectKind: string(warden.SubjectAPIKey),
		SubjectID:   keyID,
		GrantedBy:   actor.ID,
		CreatedAt:   now,
	}
	if err := st.CreateAssignment(ctx, a); err != nil {
		if errors.Is(err, warden.ErrDuplicateAssignment) {
			// A concurrent caller made the same assignment. That is fine
			// as long as the row they made grants something.
			if held, rerr := b.findLive(ctx, tenantID, keyID, r.ID, time.Now().UTC()); rerr == nil && held {
				return nil
			}
		}
		return fmt.Errorf("keysmithbridge: assign role %q to key %q: %w", roleSlug, keyID, err)
	}

	b.eng.InvalidateSubject(ctx, tenantID, warden.SubjectAPIKey, keyID)
	if pl := b.eng.Plugins(); pl != nil {
		pl.EmitRoleAssigned(ctx, a)
		pl.EmitAudit(ctx, plugin.Event{
			Actor: actor, At: now, Action: "assignment.created",
			TenantID: tenantID, EntityID: a.ID.String(), Entity: a,
		})
	}
	return nil
}

// UnassignRoleFromAPIKey removes every assignment the API key keyID holds in
// the tenant, whatever the role, namespace or resource scope. A key with no
// assignments is a no-op.
func (b *Bridge) UnassignRoleFromAPIKey(ctx context.Context, tenantID, keyID string) error {
	if err := b.ready(tenantID); err != nil {
		return err
	}
	if keyID == "" {
		return errors.New("keysmithbridge: key ID is required")
	}

	st := b.eng.Store()
	actor := b.actorFor(ctx)
	removed := 0
	// Whatever happens below, a key that lost some assignments must not keep
	// answering from its cached decisions.
	defer func() {
		if removed > 0 {
			b.eng.InvalidateSubject(ctx, tenantID, warden.SubjectAPIKey, keyID)
		}
	}()

	for {
		rows, err := st.ListAssignments(ctx, &assignment.ListFilter{
			TenantID:    tenantID,
			SubjectKind: string(warden.SubjectAPIKey),
			SubjectID:   keyID,
			Limit:       pageSize,
		})
		if err != nil {
			return fmt.Errorf("keysmithbridge: list assignments for key %q: %w", keyID, err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, a := range rows {
			if err := st.DeleteAssignment(ctx, tenantID, a.ID); err != nil {
				if errors.Is(err, warden.ErrAssignmentNotFound) {
					continue // someone else removed it first
				}
				return fmt.Errorf("keysmithbridge: remove assignment %s from key %q: %w", a.ID, keyID, err)
			}
			removed++
			if pl := b.eng.Plugins(); pl != nil {
				pl.EmitRoleUnassigned(ctx, a)
				pl.EmitAudit(ctx, plugin.Event{
					Actor: actor, At: time.Now().UTC(), Action: "assignment.deleted",
					TenantID: tenantID, EntityID: a.ID.String(), Before: a,
				})
			}
		}
		if len(rows) < pageSize {
			return nil
		}
	}
}

// SyncScopesToPermissions makes sure a permission exists for every scope, in
// the tenant's root namespace. Keysmith writes a scope action first, so
// "read:users" becomes the permission "users:read" with resource "users" and
// action "read". A scope with no colon, such as "read", is skipped without an
// error, because it covers every resource and only a wildcard could say that.
// See the package comment for the full mapping. Permissions that already
// exist are left alone, and a concurrent create of the same permission counts
// as success.
//
// Every scope is tried even when an earlier one fails. The returned error
// joins one error per scope that could not be synced, each naming its scope.
func (b *Bridge) SyncScopesToPermissions(ctx context.Context, tenantID string, scopes []string) error {
	if err := b.ready(tenantID); err != nil {
		return err
	}

	var errs []error
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		name, resource, action, skip, err := permissionFor(scope)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if skip {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		if err := b.ensurePermission(ctx, tenantID, name, resource, action); err != nil {
			errs = append(errs, fmt.Errorf("keysmithbridge: sync scope %q: %w", scope, err))
		}
	}
	return errors.Join(errs...)
}

// ensurePermission creates the permission unless it already exists.
func (b *Bridge) ensurePermission(ctx context.Context, tenantID, name, resource, action string) error {
	st := b.eng.Store()
	existing, err := st.GetPermissionByName(ctx, tenantID, "", name)
	switch {
	case err == nil && existing != nil:
		return nil
	case err != nil && !errors.Is(err, warden.ErrNotFound):
		return err
	}

	actor := b.actorFor(ctx)
	now := time.Now().UTC()
	p := &permission.Permission{
		ID:        id.NewPermissionID(),
		TenantID:  tenantID,
		Name:      name,
		Resource:  resource,
		Action:    action,
		CreatedBy: actor.ID,
		UpdatedBy: actor.ID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.CreatePermission(ctx, p); err != nil {
		if errors.Is(err, warden.ErrDuplicatePermission) {
			return nil
		}
		return err
	}

	b.eng.InvalidateTenant(ctx, tenantID)
	if pl := b.eng.Plugins(); pl != nil {
		pl.EmitPermissionCreated(ctx, p)
		pl.EmitAudit(ctx, plugin.Event{
			Actor: actor, At: now, Action: "permission.created",
			TenantID: tenantID, EntityID: p.ID.String(), Entity: p,
		})
	}
	return nil
}

// findLive reports whether the key already holds the role at the tenant root
// with no resource scope, and the grant has not expired.
func (b *Bridge) findLive(ctx context.Context, tenantID, keyID string, roleID id.RoleID, now time.Time) (bool, error) {
	root := ""
	rows, err := b.eng.Store().ListAssignments(ctx, &assignment.ListFilter{
		TenantID:      tenantID,
		NamespacePath: &root,
		RoleID:        &roleID,
		SubjectKind:   string(warden.SubjectAPIKey),
		SubjectID:     keyID,
	})
	if err != nil {
		return false, fmt.Errorf("keysmithbridge: list assignments for key %q: %w", keyID, err)
	}
	for _, a := range rows {
		if a.ResourceType == "" && a.ResourceID == "" && assignment.IsLive(a, now) {
			return true, nil
		}
	}
	return false, nil
}

// ready refuses a bridge with no engine and a call with no tenant.
func (b *Bridge) ready(tenantID string) error {
	if b == nil || b.eng == nil {
		return errors.New("keysmithbridge: no warden engine")
	}
	if tenantID == "" {
		return warden.ErrTenantRequired
	}
	return nil
}

// actorFor prefers the actor already on the context, then the bridge's own.
func (b *Bridge) actorFor(ctx context.Context) warden.Actor {
	if a, ok := warden.ActorFromContext(ctx); ok {
		return a
	}
	return b.actor
}

// permissionFor maps a keysmith scope onto a permission name, resource and
// action. Keysmith puts the action first ("read:users"), so the split is at
// the first colon and the resource is everything after it. The name follows
// Warden's own convention, resource then action. skip is true for a scope
// with no colon: it names an action on every resource, which only a wildcard
// permission could express.
func permissionFor(scope string) (name, resource, action string, skip bool, err error) {
	if strings.TrimSpace(scope) == "" {
		return "", "", "", false, errors.New("keysmithbridge: a scope name cannot be empty")
	}
	if strings.Contains(scope, "*") {
		return "", "", "", false, fmt.Errorf("keysmithbridge: scope %q contains a wildcard, and the bridge never creates wildcard permissions", scope)
	}
	action, resource, found := strings.Cut(scope, ":")
	if !found {
		return "", "", "", true, nil
	}
	if strings.TrimSpace(action) == "" || strings.TrimSpace(resource) == "" {
		return "", "", "", false, fmt.Errorf("keysmithbridge: scope %q needs an action and a resource on both sides of the first colon", scope)
	}
	return resource + ":" + action, resource, action, false, nil
}
