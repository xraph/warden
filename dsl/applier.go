package dsl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// declarativeActor identifies the DSL applier as the actor for every
// mutation it performs, for CreatedBy/UpdatedBy columns and the audit
// trail. It is warden.SystemActor with Via overridden to "declarative" so
// an audit event can distinguish an apply from other system-originated
// writes (maintenance, migrations) that also use SystemActor.
var declarativeActor = warden.Actor{Kind: warden.SystemActor.Kind, ID: warden.SystemActor.ID, Via: "declarative"}

// ApplyOptions configures the DSL applier.
type ApplyOptions struct {
	// TenantID overrides Program.Tenant when non-empty.
	TenantID string
	// AppID overrides Program.App when non-empty.
	AppID string
	// DryRun, when true, plans the changes and returns the diff but writes
	// nothing to the store.
	DryRun bool
	// Prune, when true, deletes tenant entries (within the namespaces
	// covered by the program) that are not declared in the program.
	// kubectl-style apply with prune.
	//
	// A namespace is covered when the program declares something in it
	// (an entity, or a `namespace` block, even an empty one). The tenant
	// root is covered only when the program declares something at the root.
	// Coverage is exact, not a prefix: covering "eng" does not cover
	// "eng/platform". An entity in an uncovered namespace is never pruned,
	// so a source that says nothing about a namespace cannot delete it.
	Prune bool
	// Now is the time used for CreatedAt/UpdatedAt timestamps. Defaults to
	// time.Now().UTC().
	Now time.Time
}

// ApplyResult summarizes the outcome of an apply.
type ApplyResult struct {
	Created []string // human-readable summary lines: "+ kind/name"
	Updated []string // "~ kind/name (field: old → new)"
	Deleted []string // "- kind/name"
	NoOps   int      // count of unchanged entries
}

// Apply materializes the program against the engine's store. It is
// idempotent — applying the same program twice produces the same state.
//
// Tenant scope is optional. When neither opts.TenantID nor `tenant`
// in source is set, every entity is written with an empty `tenant_id`
// — the **global scope**. Single-tenant apps that never call
// `warden.WithTenant` see this as the natural default; multi-tenant
// apps should always pass a tenant explicitly to avoid accidentally
// landing entities in the global bucket.
func Apply(ctx context.Context, eng *warden.Engine, prog *Program, opts ApplyOptions) (*ApplyResult, error) {
	tenantID := firstNonEmpty(opts.TenantID, prog.Tenant)
	if opts.Prune && tenantID == "" {
		return nil, errors.New("dsl: Prune requires a tenant: set ApplyOptions.TenantID or `tenant` in source; pruning the global (tenant-less) scope would delete every entity with an empty tenant_id across every caller that also uses the global scope")
	}
	if errs := Resolve(prog); len(errs) > 0 {
		return nil, &DiagnosticError{Diags: errs}
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	a := &applier{
		ctx:      ctx,
		eng:      eng,
		store:    eng.Store(),
		tenantID: tenantID,
		appID:    firstNonEmpty(opts.AppID, prog.App),
		now:      now,
		prune:    opts.Prune,
		dryRun:   opts.DryRun,
		result:   &ApplyResult{},
		covered:  coveredNamespaces(prog),
	}
	if err := a.run(prog); err != nil {
		return nil, err
	}
	return a.result, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type applier struct {
	ctx   context.Context
	eng   *warden.Engine
	store interface {
		// Roles
		CreateRole(ctx context.Context, r *role.Role) error
		GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*role.Role, error)
		UpdateRole(ctx context.Context, r *role.Role) error
		DeleteRole(ctx context.Context, tenantID string, roleID id.RoleID) error
		ListRoles(ctx context.Context, filter *role.ListFilter) ([]*role.Role, error)
		// Permissions
		CreatePermission(ctx context.Context, p *permission.Permission) error
		GetPermissionByName(ctx context.Context, tenantID, namespacePath, name string) (*permission.Permission, error)
		UpdatePermission(ctx context.Context, p *permission.Permission) error
		DeletePermission(ctx context.Context, tenantID string, permID id.PermissionID) error
		ListPermissions(ctx context.Context, filter *permission.ListFilter) ([]*permission.Permission, error)
		SetRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID, refs []permission.Ref) error
		// Policies
		CreatePolicy(ctx context.Context, p *policy.Policy) error
		GetPolicyByName(ctx context.Context, tenantID, namespacePath, name string) (*policy.Policy, error)
		UpdatePolicy(ctx context.Context, p *policy.Policy) error
		DeletePolicy(ctx context.Context, tenantID string, polID id.PolicyID) error
		ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error)
		// Resource types
		CreateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error
		GetResourceTypeByName(ctx context.Context, tenantID, namespacePath, name string) (*resourcetype.ResourceType, error)
		UpdateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error
		DeleteResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) error
		ListResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error)
		// Relations
		CreateRelation(ctx context.Context, t *relation.Tuple) error
		ListRelations(ctx context.Context, filter *relation.ListFilter) ([]*relation.Tuple, error)
	}

	tenantID string
	appID    string
	now      time.Time
	prune    bool
	dryRun   bool

	// covered is the set of namespace paths the program declares something
	// in. Prune only considers entities whose namespace is in it.
	covered map[string]struct{}

	result *ApplyResult
}

// coveredNamespaces returns the namespace paths the program declares
// something in: the path of every entity, and of every `namespace` block
// (walked with the same joining rule the parser flattens with).
func coveredNamespaces(prog *Program) map[string]struct{} {
	out := make(map[string]struct{})
	for _, rt := range prog.ResourceTypes {
		out[rt.NamespacePath] = struct{}{}
	}
	for _, p := range prog.Permissions {
		out[p.NamespacePath] = struct{}{}
	}
	for _, r := range prog.Roles {
		out[r.NamespacePath] = struct{}{}
	}
	for _, p := range prog.Policies {
		out[p.NamespacePath] = struct{}{}
	}
	for _, r := range prog.Relations {
		out[r.NamespacePath] = struct{}{}
	}
	var walk func(parent string, nss []*NamespaceDecl)
	walk = func(parent string, nss []*NamespaceDecl) {
		for _, ns := range nss {
			abs := joinNS(parent, ns.Name)
			out[abs] = struct{}{}
			walk(abs, ns.Namespaces)
		}
	}
	walk("", prog.Namespaces)
	return out
}

// covers reports whether prune may delete entities in namespacePath.
func (a *applier) covers(namespacePath string) bool {
	_, ok := a.covered[namespacePath]
	return ok
}

// emitAudit records one audit event for a declarative mutation, through
// the same plugin.Registry.EmitAudit hook every HTTP handler uses. A
// no-op on a dry run (nothing was actually written) or when the engine
// has no plugin registry configured.
//
// Each entity kind uses its normal typed action ("role.created",
// "policy.updated", "relation.deleted", ...) rather than a single generic
// "declarative.applied" for every mutation, so an Audit plugin filtering
// on action names doesn't need a separate code path for declarative
// applies versus API-driven ones; Actor.Via distinguishes the two.
func (a *applier) emitAudit(action, entityID string, entity, before any) {
	if a.dryRun || a.eng.Plugins() == nil {
		return
	}
	a.eng.Plugins().EmitAudit(a.ctx, plugin.Event{
		Actor:    declarativeActor,
		At:       a.now,
		Action:   action,
		TenantID: a.tenantID,
		EntityID: entityID,
		Entity:   entity,
		Before:   before,
	})
}

func (a *applier) run(prog *Program) error {
	if err := a.applyResourceTypes(prog); err != nil {
		return err
	}
	if err := a.applyPermissions(prog); err != nil {
		return err
	}
	if err := a.applyRoles(prog); err != nil {
		return err
	}
	if err := a.applyRolePermissions(prog); err != nil {
		return err
	}
	if err := a.applyPolicies(prog); err != nil {
		return err
	}
	return a.applyRelations(prog)
}

// ─────────────────────────────────────────────────────────────────────────
// Resource types.
// ─────────────────────────────────────────────────────────────────────────

func (a *applier) applyResourceTypes(prog *Program) error {
	declared := make(map[string]struct{})
	for _, rt := range prog.ResourceTypes {
		declared[keyOf(rt.NamespacePath, rt.Name)] = struct{}{}
		desired := &resourcetype.ResourceType{
			TenantID:      a.tenantID,
			NamespacePath: rt.NamespacePath,
			AppID:         a.appID,
			Name:          rt.Name,
			Description:   rt.Description,
			Relations:     rtRelations(rt),
			Permissions:   rtPermissions(rt),
			CreatedBy:     declarativeActor.ID,
			UpdatedBy:     declarativeActor.ID,
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetResourceTypeByName(a.ctx, a.tenantID, rt.NamespacePath, rt.Name) //nolint:errcheck // missing → create
		if existing == nil {
			// ID is auto-assigned by the store on CreateResourceType.
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ resource_type/%s/%s", rt.NamespacePath, rt.Name))
			if !a.dryRun {
				if err := a.store.CreateResourceType(a.ctx, desired); err != nil && !errors.Is(err, warden.ErrAlreadyExists) {
					return fmt.Errorf("create resource type %s: %w", rt.Name, err)
				}
				a.emitAudit("resourcetype.created", desired.ID.String(), desired, nil)
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		desired.CreatedBy = existing.CreatedBy
		if rtEquivalent(existing, desired) {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, fmt.Sprintf("~ resource_type/%s/%s", rt.NamespacePath, rt.Name))
		if !a.dryRun {
			if err := a.store.UpdateResourceType(a.ctx, desired); err != nil {
				return fmt.Errorf("update resource type %s: %w", rt.Name, err)
			}
			a.emitAudit("resourcetype.updated", desired.ID.String(), desired, existing)
		}
	}
	if a.prune {
		if err := a.pruneResourceTypes(declared); err != nil {
			return err
		}
	}
	return nil
}

func rtRelations(rt *ResourceDecl) []resourcetype.RelationDef {
	out := make([]resourcetype.RelationDef, 0, len(rt.Relations))
	for _, rel := range rt.Relations {
		var subjects []string
		for _, s := range rel.AllowedSubjects {
			if s.Relation == "" {
				subjects = append(subjects, s.Type)
			} else {
				subjects = append(subjects, s.Type+"#"+s.Relation)
			}
		}
		out = append(out, resourcetype.RelationDef{Name: rel.Name, AllowedSubjects: subjects})
	}
	return out
}

func rtPermissions(rt *ResourceDecl) []resourcetype.PermissionDef {
	out := make([]resourcetype.PermissionDef, 0, len(rt.Permissions))
	for _, p := range rt.Permissions {
		out = append(out, resourcetype.PermissionDef{
			Name:       p.Name,
			Expression: FormatExpr(p.Expr),
		})
	}
	return out
}

func rtEquivalent(a, b *resourcetype.ResourceType) bool {
	if a.Description != b.Description {
		return false
	}
	if len(a.Relations) != len(b.Relations) || len(a.Permissions) != len(b.Permissions) {
		return false
	}
	for i := range a.Relations {
		if a.Relations[i].Name != b.Relations[i].Name {
			return false
		}
		if strings.Join(a.Relations[i].AllowedSubjects, ",") != strings.Join(b.Relations[i].AllowedSubjects, ",") {
			return false
		}
	}
	for i := range a.Permissions {
		if a.Permissions[i].Name != b.Permissions[i].Name || a.Permissions[i].Expression != b.Permissions[i].Expression {
			return false
		}
	}
	return true
}

func (a *applier) pruneResourceTypes(declared map[string]struct{}) error {
	existing, err := collectPages(func(limit, offset int) ([]*resourcetype.ResourceType, error) {
		return a.store.ListResourceTypes(a.ctx, &resourcetype.ListFilter{
			TenantID: a.tenantID, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return err
	}
	for _, rt := range existing {
		if !a.covers(rt.NamespacePath) {
			continue
		}
		if _, ok := declared[keyOf(rt.NamespacePath, rt.Name)]; ok {
			continue
		}
		a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- resource_type/%s/%s", rt.NamespacePath, rt.Name))
		if !a.dryRun {
			if err := a.store.DeleteResourceType(a.ctx, a.tenantID, rt.ID); err != nil {
				return fmt.Errorf("delete resource type %s: %w", rt.Name, err)
			}
			a.emitAudit("resourcetype.deleted", rt.ID.String(), nil, rt)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Permissions.
// ─────────────────────────────────────────────────────────────────────────

func (a *applier) applyPermissions(prog *Program) error {
	declared := make(map[string]struct{})
	for _, p := range prog.Permissions {
		declared[keyOf(p.NamespacePath, p.Name)] = struct{}{}
		desired := &permission.Permission{
			TenantID:      a.tenantID,
			NamespacePath: p.NamespacePath,
			AppID:         a.appID,
			Name:          p.Name,
			Description:   p.Description,
			Resource:      p.Resource,
			Action:        p.Action,
			IsSystem:      p.IsSystem,
			CreatedBy:     declarativeActor.ID,
			UpdatedBy:     declarativeActor.ID,
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetPermissionByName(a.ctx, a.tenantID, p.NamespacePath, p.Name) //nolint:errcheck // missing → create
		if existing == nil {
			// ID is auto-assigned by the store on CreatePermission.
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ permission/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.CreatePermission(a.ctx, desired); err != nil && !errors.Is(err, warden.ErrAlreadyExists) {
					return fmt.Errorf("create permission %s: %w", p.Name, err)
				}
				a.emitAudit("permission.created", desired.ID.String(), desired, nil)
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		desired.CreatedBy = existing.CreatedBy
		if existing.Description == desired.Description &&
			existing.Resource == desired.Resource &&
			existing.Action == desired.Action &&
			existing.IsSystem == desired.IsSystem &&
			existing.NamespacePath == desired.NamespacePath {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, fmt.Sprintf("~ permission/%s/%s", p.NamespacePath, p.Name))
		if !a.dryRun {
			if err := a.store.UpdatePermission(a.ctx, desired); err != nil {
				return fmt.Errorf("update permission %s: %w", p.Name, err)
			}
			a.emitAudit("permission.updated", desired.ID.String(), desired, existing)
		}
	}
	if a.prune {
		existing, err := collectPages(func(limit, offset int) ([]*permission.Permission, error) {
			return a.store.ListPermissions(a.ctx, &permission.ListFilter{
				TenantID: a.tenantID, Limit: limit, Offset: offset,
			})
		})
		if err != nil {
			return err
		}
		for _, p := range existing {
			if !a.covers(p.NamespacePath) {
				continue
			}
			if _, ok := declared[keyOf(p.NamespacePath, p.Name)]; ok {
				continue
			}
			a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- permission/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.DeletePermission(a.ctx, a.tenantID, p.ID); err != nil {
					return fmt.Errorf("delete permission %s: %w", p.Name, err)
				}
				a.emitAudit("permission.deleted", p.ID.String(), nil, p)
			}
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Roles (toposorted by parent slug).
// ─────────────────────────────────────────────────────────────────────────

func (a *applier) applyRoles(prog *Program) error {
	sorted, err := topoSortRoles(prog.Roles)
	if err != nil {
		return err
	}
	declared := make(map[string]struct{})
	for _, r := range sorted {
		declared[keyOf(r.NamespacePath, r.Slug)] = struct{}{}
		desired := &role.Role{
			TenantID:      a.tenantID,
			NamespacePath: r.NamespacePath,
			AppID:         a.appID,
			Name:          firstNonEmpty(r.Name, r.Slug),
			Description:   r.Description,
			Slug:          r.Slug,
			IsSystem:      r.IsSystem,
			IsDefault:     r.IsDefault,
			ParentSlug:    parentSlugForStorage(r.Parent),
			MaxMembers:    r.MaxMembers,
			CreatedBy:     declarativeActor.ID,
			UpdatedBy:     declarativeActor.ID,
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetRoleBySlug(a.ctx, a.tenantID, r.NamespacePath, r.Slug) //nolint:errcheck // missing → create
		if existing == nil {
			// ID is auto-assigned by the store on CreateRole.
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ role/%s/%s", r.NamespacePath, r.Slug))
			if !a.dryRun {
				if err := a.store.CreateRole(a.ctx, desired); err != nil && !errors.Is(err, warden.ErrAlreadyExists) {
					return fmt.Errorf("create role %s: %w", r.Slug, err)
				}
				a.emitAudit("role.created", desired.ID.String(), desired, nil)
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		desired.CreatedBy = existing.CreatedBy
		if existing.Name == desired.Name &&
			existing.Description == desired.Description &&
			existing.IsSystem == desired.IsSystem &&
			existing.IsDefault == desired.IsDefault &&
			existing.ParentSlug == desired.ParentSlug &&
			existing.MaxMembers == desired.MaxMembers &&
			existing.NamespacePath == desired.NamespacePath {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, fmt.Sprintf("~ role/%s/%s", r.NamespacePath, r.Slug))
		if !a.dryRun {
			if err := a.store.UpdateRole(a.ctx, desired); err != nil {
				return fmt.Errorf("update role %s: %w", r.Slug, err)
			}
			a.emitAudit("role.updated", desired.ID.String(), desired, existing)
		}
	}
	if a.prune {
		existing, err := collectPages(func(limit, offset int) ([]*role.Role, error) {
			return a.store.ListRoles(a.ctx, &role.ListFilter{
				TenantID: a.tenantID, Limit: limit, Offset: offset,
			})
		})
		if err != nil {
			return err
		}
		for _, r := range existing {
			if !a.covers(r.NamespacePath) {
				continue
			}
			if _, ok := declared[keyOf(r.NamespacePath, r.Slug)]; ok {
				continue
			}
			if r.IsSystem {
				continue // system roles are protected from prune
			}
			a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- role/%s/%s", r.NamespacePath, r.Slug))
			if !a.dryRun {
				if err := a.store.DeleteRole(a.ctx, a.tenantID, r.ID); err != nil {
					return fmt.Errorf("delete role %s: %w", r.Slug, err)
				}
				a.emitAudit("role.deleted", r.ID.String(), nil, r)
			}
		}
	}
	return nil
}

// parentSlugForStorage strips the absolute-path leading "/" from a parent
// reference. Local-form refs are stored as-is since the storage column only
// holds the slug, not the namespace.
func parentSlugForStorage(parent string) string {
	if !strings.HasPrefix(parent, "/") {
		return parent
	}
	rest := parent[1:]
	idx := strings.LastIndex(rest, "/")
	if idx < 0 {
		return rest
	}
	return rest[idx+1:]
}

// applyRolePermissions sets each role's permission attachments from the DSL's
// `grants` lists. Resolves permission name → ID at apply time.
//
// When DryRun is set, neither the role nor the permissions exist in the
// store yet (we skipped the writes), so a grant resolves against the
// program's own permissions first and the store second. Both follow the
// same lookup the real apply uses (grantResolves): the role's own
// namespace, then the tenant root. An unknown grant is a diagnostic at the
// role's position, so a caller can show it next to the source.
func (a *applier) applyRolePermissions(prog *Program) error {
	if a.dryRun {
		// Permissions the program declares stand in for the writes a dry
		// run skipped. Keyed by namespace and name, as the real apply finds
		// them.
		declared := make(map[string]struct{}, len(prog.Permissions))
		for _, p := range prog.Permissions {
			declared[keyOf(p.NamespacePath, p.Name)] = struct{}{}
		}
		var diags []*Diagnostic
		for _, r := range prog.Roles {
			for _, name := range r.Grants {
				if a.grantResolves(r.NamespacePath, name, declared) {
					continue
				}
				diags = append(diags, unknownGrant(r, name))
			}
		}
		if len(diags) > 0 {
			return &DiagnosticError{Diags: diags}
		}
		return nil
	}

	for _, r := range prog.Roles {
		if len(r.Grants) == 0 && !r.GrantsAppend {
			continue
		}
		// Re-fetch the role to get its ID (just-created or pre-existing).
		stored, err := a.store.GetRoleBySlug(a.ctx, a.tenantID, r.NamespacePath, r.Slug)
		if err != nil || stored == nil {
			return fmt.Errorf("role %s not found after apply: %w", r.Slug, err)
		}
		// Phase A.5: junction is keyed by natural keys, so the applier no
		// longer needs to resolve perm name → typeid. We still call
		// GetPermissionByName as an existence check so a missing perm fails
		// fast at apply time rather than silently writing an orphan grant.
		refs := make([]permission.Ref, 0, len(r.Grants))
		for _, name := range r.Grants {
			perm := a.lookupGrant(r.NamespacePath, name)
			if perm == nil {
				return &DiagnosticError{Diags: []*Diagnostic{unknownGrant(r, name)}}
			}
			refs = append(refs, permission.Ref{
				NamespacePath: perm.NamespacePath,
				Name:          perm.Name,
			})
		}
		if err := a.store.SetRolePermissions(a.ctx, a.tenantID, stored.ID, refs); err != nil {
			return fmt.Errorf("set permissions for role %s: %w", r.Slug, err)
		}
	}
	return nil
}

// lookupGrant finds the permission a role in namespacePath grants by name.
// It looks in the role's namespace first. If not found, it falls back to the
// root namespace ("") so that roles in a child namespace (e.g. "platform")
// can reference permissions declared in the shared catalog at the root
// level. It returns nil when neither has it.
func (a *applier) lookupGrant(namespacePath, name string) *permission.Permission {
	perm, err := a.store.GetPermissionByName(a.ctx, a.tenantID, namespacePath, name)
	if (err != nil || perm == nil) && namespacePath != "" {
		perm, err = a.store.GetPermissionByName(a.ctx, a.tenantID, "", name)
	}
	if err != nil || perm == nil {
		return nil
	}
	return perm
}

// grantResolves is lookupGrant for a dry run: a permission the program
// declares counts as present, under the same namespace-then-root rule.
func (a *applier) grantResolves(namespacePath, name string, declared map[string]struct{}) bool {
	if _, ok := declared[keyOf(namespacePath, name)]; ok {
		return true
	}
	if namespacePath != "" {
		if _, ok := declared[keyOf("", name)]; ok {
			return true
		}
	}
	return a.lookupGrant(namespacePath, name) != nil
}

func unknownGrant(r *RoleDecl, name string) *Diagnostic {
	return &Diagnostic{Pos: r.Pos, Msg: fmt.Sprintf("role %s grants unknown permission %q", r.Slug, name)}
}

// ─────────────────────────────────────────────────────────────────────────
// Policies.
// ─────────────────────────────────────────────────────────────────────────

func (a *applier) applyPolicies(prog *Program) error {
	declared := make(map[string]struct{})
	for _, p := range prog.Policies {
		declared[keyOf(p.NamespacePath, p.Name)] = struct{}{}
		desired := &policy.Policy{
			TenantID:      a.tenantID,
			NamespacePath: p.NamespacePath,
			AppID:         a.appID,
			Name:          p.Name,
			Description:   p.Description,
			Effect:        policy.Effect(p.Effect),
			Priority:      p.Priority,
			IsActive:      p.Active,
			NotBefore:     p.NotBefore,
			NotAfter:      p.NotAfter,
			Obligations:   p.Obligations,
			Version:       1,
			Actions:       p.Actions,
			Resources:     p.Resources,
			Conditions:    flattenConditions(p.Conditions),
			CreatedBy:     declarativeActor.ID,
			UpdatedBy:     declarativeActor.ID,
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetPolicyByName(a.ctx, a.tenantID, p.NamespacePath, p.Name) //nolint:errcheck // missing → create
		if existing == nil {
			// ID is auto-assigned by the store on CreatePolicy.
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ policy/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.CreatePolicy(a.ctx, desired); err != nil && !errors.Is(err, warden.ErrAlreadyExists) {
					return fmt.Errorf("create policy %s: %w", p.Name, err)
				}
				a.emitAudit("policy.created", desired.ID.String(), desired, nil)
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		desired.CreatedBy = existing.CreatedBy
		desired.Version = existing.Version + 1
		if policyEquivalent(existing, desired) {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, fmt.Sprintf("~ policy/%s/%s", p.NamespacePath, p.Name))
		if !a.dryRun {
			if err := a.store.UpdatePolicy(a.ctx, desired); err != nil {
				return fmt.Errorf("update policy %s: %w", p.Name, err)
			}
			a.emitAudit("policy.updated", desired.ID.String(), desired, existing)
		}
	}
	if a.prune {
		existing, err := collectPages(func(limit, offset int) ([]*policy.Policy, error) {
			return a.store.ListPolicies(a.ctx, &policy.ListFilter{
				TenantID: a.tenantID, Limit: limit, Offset: offset,
			})
		})
		if err != nil {
			return err
		}
		for _, p := range existing {
			if !a.covers(p.NamespacePath) {
				continue
			}
			if _, ok := declared[keyOf(p.NamespacePath, p.Name)]; ok {
				continue
			}
			a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- policy/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.DeletePolicy(a.ctx, a.tenantID, p.ID); err != nil {
					return fmt.Errorf("delete policy %s: %w", p.Name, err)
				}
				a.emitAudit("policy.deleted", p.ID.String(), nil, p)
			}
		}
	}
	return nil
}

func policyEquivalent(a, b *policy.Policy) bool {
	if a.NamespacePath != b.NamespacePath {
		return false
	}
	if a.Description != b.Description || a.Effect != b.Effect ||
		a.Priority != b.Priority || a.IsActive != b.IsActive {
		return false
	}
	if !timePtrEqual(a.NotBefore, b.NotBefore) || !timePtrEqual(a.NotAfter, b.NotAfter) {
		return false
	}
	if strings.Join(a.Obligations, ",") != strings.Join(b.Obligations, ",") {
		return false
	}
	if strings.Join(a.Actions, ",") != strings.Join(b.Actions, ",") {
		return false
	}
	if strings.Join(a.Resources, ",") != strings.Join(b.Resources, ",") {
		return false
	}
	if len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		if a.Conditions[i].Field != b.Conditions[i].Field ||
			a.Conditions[i].Operator != b.Conditions[i].Operator {
			return false
		}
		// Value comparison via fmt round-trip — covers most literal types
		// without pulling in reflect.DeepEqual cost on the hot path.
		if fmt.Sprintf("%v", a.Conditions[i].Value) != fmt.Sprintf("%v", b.Conditions[i].Value) {
			return false
		}
	}
	return true
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
}

func flattenConditions(in []*Condition) []policy.Condition {
	var out []policy.Condition
	for _, c := range in {
		flatten := func(c *Condition) {
			out = append(out, policy.Condition{
				ID:       id.NewConditionID(),
				Field:    c.Field,
				Operator: policy.Operator(c.Operator),
				Value:    c.Value,
			})
		}
		switch {
		case len(c.AllOf) > 0:
			// AllOf: append each as separate AND-merged condition.
			for _, inner := range c.AllOf {
				if inner.Field != "" {
					flatten(inner)
				}
			}
		case len(c.AnyOf) > 0:
			// AnyOf in v1: not yet supported at the evaluator layer; we
			// record only the first sub-condition to avoid silent drops.
			// Future work: extend evaluator to support OR groups.
			for _, inner := range c.AnyOf {
				if inner.Field != "" {
					flatten(inner)
					break
				}
			}
		case c.Field != "":
			flatten(c)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// Relations (initial state).
// ─────────────────────────────────────────────────────────────────────────

func (a *applier) applyRelations(prog *Program) error {
	for _, r := range prog.Relations {
		// Idempotency: the relation tuple table has a UNIQUE constraint on
		// the full tuple, so creating an existing tuple is a no-op (driver-
		// dependent: we ignore the error class for now).
		// ID is auto-assigned by the store on CreateRelation.
		t := &relation.Tuple{
			TenantID:        a.tenantID,
			NamespacePath:   r.NamespacePath,
			AppID:           a.appID,
			ObjectType:      r.ObjectType,
			ObjectID:        r.ObjectID,
			Relation:        r.Relation,
			SubjectType:     r.SubjectType,
			SubjectID:       r.SubjectID,
			SubjectRelation: r.SubjectRelation,
			CreatedBy:       declarativeActor.ID,
			CreatedAt:       a.now,
		}
		// Check if the tuple already exists. The filter pins every column
		// but the namespace, so this normally comes back in one page; it
		// pages anyway so a tenant with many namespaces cannot hide a
		// duplicate behind the store's default limit.
		existing, _ := collectPages(func(limit, offset int) ([]*relation.Tuple, error) { //nolint:errcheck // empty list → create
			return a.store.ListRelations(a.ctx, &relation.ListFilter{
				TenantID:        a.tenantID,
				NamespacePath:   nil, // exact-match below via SubjectRelation comparison
				ObjectType:      r.ObjectType,
				ObjectID:        r.ObjectID,
				Relation:        r.Relation,
				SubjectType:     r.SubjectType,
				SubjectID:       r.SubjectID,
				SubjectRelation: r.SubjectRelation,
				Limit:           limit,
				Offset:          offset,
			})
		})
		dup := false
		for _, e := range existing {
			if e.NamespacePath == r.NamespacePath {
				dup = true
				break
			}
		}
		if dup {
			a.result.NoOps++
			continue
		}
		a.result.Created = append(a.result.Created, fmt.Sprintf("+ relation/%s/%s:%s#%s", r.NamespacePath, r.ObjectType, r.ObjectID, r.Relation))
		if !a.dryRun {
			if err := a.store.CreateRelation(a.ctx, t); err != nil {
				return fmt.Errorf("create relation: %w", err)
			}
			a.emitAudit("relation.written", t.ID.String(), t, nil)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

// DiagnosticError is the error type Apply / ApplyFile / ApplyDir /
// ApplyFS return when source-level errors prevent application. Use
// errors.As to extract the underlying diagnostics:
//
//	var derr *dsl.DiagnosticError
//	if errors.As(err, &derr) {
//	    for _, d := range derr.Diagnostics() {
//	        fmt.Println(d) // file:line:col: message
//	    }
//	}
//
// The Error() representation joins every diagnostic with a newline so
// printing the error directly produces a multi-line list suitable for
// CI logs.
type DiagnosticError struct {
	Diags []*Diagnostic
}

func (e *DiagnosticError) Error() string {
	var b strings.Builder
	for i, d := range e.Diags {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(d.String())
	}
	return b.String()
}

// Diagnostics returns the underlying diagnostics for inspection.
func (e *DiagnosticError) Diagnostics() []*Diagnostic { return e.Diags }

// FormatExpr renders an expression AST back to its canonical textual form.
// Used by the applier to store ResourceType.Permissions[].Expression.
func FormatExpr(e Expr) string {
	switch v := e.(type) {
	case *RefExpr:
		return v.Name
	case *TraverseExpr:
		return strings.Join(v.Steps, "->")
	case *OrExpr:
		return formatExprPrec(v.Left, precOr) + " or " + formatExprPrec(v.Right, precOr)
	case *AndExpr:
		return formatExprPrec(v.Left, precAnd) + " and " + formatExprPrec(v.Right, precAnd)
	case *NotExpr:
		return "not " + formatExprPrec(v.Inner, precNot)
	}
	return ""
}

const (
	precOr = iota
	precAnd
	precNot
	precPrimary
)

func formatExprPrec(e Expr, ctx int) string {
	switch v := e.(type) {
	case *OrExpr:
		s := FormatExpr(v)
		if ctx > precOr {
			return "(" + s + ")"
		}
		return s
	case *AndExpr:
		s := FormatExpr(v)
		if ctx > precAnd {
			return "(" + s + ")"
		}
		return s
	default:
		return FormatExpr(e)
	}
}
