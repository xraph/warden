package dsl

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	Updated []string // "~ kind/ns/name (field, field)": the fields that differ
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
		declared: declaredPermissions(prog),
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
		ListRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error)
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

	// declared is the set of permissions the program declares, keyed by
	// namespace and name. Grants resolve against it and the store.
	declared map[string]struct{}

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
	// Grants are checked before anything is written, so an unknown grant
	// stops a real apply as early as it stops a dry run.
	if err := a.checkGrants(prog); err != nil {
		return err
	}
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
		desired.Metadata = existing.Metadata
		desired.AppID = a.appFor(existing.AppID)
		changed := rtChanges(existing, desired)
		if len(changed) == 0 {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, updateLine("resource_type", rt.NamespacePath, rt.Name, changed))
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

// rtChanges lists the fields of a resource type that differ, in the words
// the language uses for them. Expressions compare in canonical form: the
// store keeps an expression as it was typed, the language keeps its
// meaning, so `(viewer or owner)` and `viewer or owner` are the same.
func rtChanges(a, b *resourcetype.ResourceType) []string {
	var out []string
	if a.Description != b.Description {
		out = append(out, "description")
	}
	if a.AppID != b.AppID {
		out = append(out, "app")
	}
	relationsSame := len(a.Relations) == len(b.Relations)
	for i := 0; relationsSame && i < len(a.Relations); i++ {
		if a.Relations[i].Name != b.Relations[i].Name ||
			!stringsEqual(a.Relations[i].AllowedSubjects, b.Relations[i].AllowedSubjects) {
			relationsSame = false
		}
	}
	if !relationsSame {
		out = append(out, "relations")
	}
	permsSame := len(a.Permissions) == len(b.Permissions)
	for i := 0; permsSame && i < len(a.Permissions); i++ {
		if a.Permissions[i].Name != b.Permissions[i].Name ||
			canonicalExpr(a.Permissions[i].Expression) != canonicalExpr(b.Permissions[i].Expression) {
			permsSame = false
		}
	}
	if !permsSame {
		out = append(out, "permissions")
	}
	return out
}

// canonicalExpr is an expression's text as FormatExpr writes it, or the
// text unchanged when it does not parse.
func canonicalExpr(src string) string {
	expr, diags := CompileExpr("<stored>", src)
	if len(diags) > 0 {
		return src
	}
	return FormatExpr(expr)
}

// stringsEqual compares two lists element by element; nil and empty are
// the same list.
func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// updateLine is one `~` line: the entity and the fields that differ.
func updateLine(kind, ns, name string, fields []string) string {
	return fmt.Sprintf("~ %s/%s/%s (%s)", kind, ns, name, strings.Join(fields, ", "))
}

// appFor is the app id an update writes: the apply's own when it names
// one, and otherwise the stored one, so an apply that names no app leaves
// it alone.
//
// Metadata is carried over on every update for the same reason: the
// language has no syntax for it, so a source cannot mean to change it.
func (a *applier) appFor(stored string) string {
	if a.appID == "" {
		return stored
	}
	return a.appID
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
		desired.Metadata = existing.Metadata
		desired.AppID = a.appFor(existing.AppID)
		var changed []string
		if existing.Resource != desired.Resource {
			changed = append(changed, "resource")
		}
		if existing.Action != desired.Action {
			changed = append(changed, "action")
		}
		if existing.Description != desired.Description {
			changed = append(changed, "description")
		}
		if existing.IsSystem != desired.IsSystem {
			changed = append(changed, "is_system")
		}
		if existing.AppID != desired.AppID {
			changed = append(changed, "app")
		}
		if len(changed) == 0 {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, updateLine("permission", p.NamespacePath, p.Name, changed))
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
		desired.Metadata = existing.Metadata
		desired.AppID = a.appFor(existing.AppID)
		changed := roleChanges(existing, desired)
		roleFieldsChanged := len(changed) > 0
		grantsChanged, err := a.grantsDiffer(r, existing)
		if err != nil {
			return err
		}
		if grantsChanged {
			changed = append(changed, "grants")
		}
		if len(changed) == 0 {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, updateLine("role", r.NamespacePath, r.Slug, changed))
		// A grant-only change is written by applyRolePermissions; the role
		// row itself is left alone.
		if !a.dryRun && roleFieldsChanged {
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

// roleChanges lists the role's own fields that differ, grants aside.
func roleChanges(a, b *role.Role) []string {
	var out []string
	if a.Name != b.Name {
		out = append(out, "name")
	}
	if a.Description != b.Description {
		out = append(out, "description")
	}
	if a.IsSystem != b.IsSystem {
		out = append(out, "is_system")
	}
	if a.IsDefault != b.IsDefault {
		out = append(out, "is_default")
	}
	if a.MaxMembers != b.MaxMembers {
		out = append(out, "max_members")
	}
	if a.ParentSlug != b.ParentSlug {
		out = append(out, "parent")
	}
	if a.AppID != b.AppID {
		out = append(out, "app")
	}
	return out
}

// grantsDiffer reports whether applying r would change the stored role's
// grant set. A role without a grants clause leaves its grants alone, so it
// never differs.
func (a *applier) grantsDiffer(r *RoleDecl, stored *role.Role) (bool, error) {
	if !grantsManaged(r) {
		return false, nil
	}
	current, err := a.store.ListRolePermissions(a.ctx, a.tenantID, stored.ID)
	if err != nil {
		return false, fmt.Errorf("list grants for role %s: %w", r.Slug, err)
	}
	have := make(map[string]struct{}, len(current))
	for _, p := range current {
		have[keyOf(p.NamespacePath, p.Name)] = struct{}{}
	}
	// Unknown grants were refused by checkGrants before anything ran.
	refs, _ := a.desiredGrants(r)
	want := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		want[keyOf(ref.NamespacePath, ref.Name)] = struct{}{}
	}
	if len(have) != len(want) {
		return true, nil
	}
	for k := range want {
		if _, ok := have[k]; !ok {
			return true, nil
		}
	}
	return false, nil
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

// grantsManaged reports whether the program sets the role's grants. A
// role with a `grants` clause (even `grants = []`) owns its whole grant
// set; a role without one leaves the stored grants alone.
func grantsManaged(r *RoleDecl) bool {
	return r.GrantsSet || r.GrantsAppend || len(r.Grants) > 0 || len(r.QualifiedGrants) > 0
}

// declaredPermissions indexes the program's permissions by namespace and
// name.
func declaredPermissions(prog *Program) map[string]struct{} {
	out := make(map[string]struct{}, len(prog.Permissions))
	for _, p := range prog.Permissions {
		out[keyOf(p.NamespacePath, p.Name)] = struct{}{}
	}
	return out
}

// permExists reports whether a permission will exist once this apply has
// written its permissions: the program declares it, or the store holds it
// and prune will not delete it. A dry run and a real apply answer the same,
// because neither depends on the permission writes having happened.
func (a *applier) permExists(ns, name string) bool {
	if _, ok := a.declared[keyOf(ns, name)]; ok {
		return true
	}
	if a.prune && a.covers(ns) {
		// Undeclared in a covered namespace: prune deletes it.
		return false
	}
	perm, err := a.store.GetPermissionByName(a.ctx, a.tenantID, ns, name)
	return err == nil && perm != nil
}

// resolveGrant finds the permission a bare grant names. It looks in the
// role's namespace first. If not found, it falls back to the root namespace
// ("") so that roles in a child namespace (e.g. "platform") can reference
// permissions declared in the shared catalog at the root level. Only these
// two are searched; a permission anywhere else needs a qualified grant.
func (a *applier) resolveGrant(roleNS, name string) (permission.Ref, bool) {
	if a.permExists(roleNS, name) {
		return permission.Ref{NamespacePath: roleNS, Name: name}, true
	}
	if roleNS != "" && a.permExists("", name) {
		return permission.Ref{NamespacePath: "", Name: name}, true
	}
	return permission.Ref{}, false
}

// desiredGrants resolves a role's grants to the permission refs the apply
// writes, with one diagnostic per grant that names no permission.
func (a *applier) desiredGrants(r *RoleDecl) ([]permission.Ref, []*Diagnostic) {
	var diags []*Diagnostic
	refs := make([]permission.Ref, 0, len(r.Grants)+len(r.QualifiedGrants))
	seen := make(map[string]struct{})
	add := func(ref permission.Ref) {
		k := keyOf(ref.NamespacePath, ref.Name)
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		refs = append(refs, ref)
	}
	for _, name := range r.Grants {
		ref, ok := a.resolveGrant(r.NamespacePath, name)
		if !ok {
			diags = append(diags, unknownGrant(r, name))
			continue
		}
		add(ref)
	}
	for _, g := range r.QualifiedGrants {
		if !a.permExists(g.NamespacePath, g.Name) {
			diags = append(diags, &Diagnostic{Pos: g.Pos, Msg: fmt.Sprintf(
				"role %s grants unknown permission %q in namespace %q", r.Slug, g.Name, g.NamespacePath)})
			continue
		}
		add(permission.Ref{NamespacePath: g.NamespacePath, Name: g.Name})
	}
	return refs, diags
}

// checkGrants refuses a program with a grant that names no permission, as
// a diagnostic at the role, before the apply writes anything. A dry run and
// a real apply report every bad grant the same way.
func (a *applier) checkGrants(prog *Program) error {
	var diags []*Diagnostic
	for _, r := range prog.Roles {
		_, ds := a.desiredGrants(r)
		diags = append(diags, ds...)
	}
	if len(diags) > 0 {
		return &DiagnosticError{Diags: diags}
	}
	return nil
}

// applyRolePermissions sets each role's grant set from its `grants`
// clause. Grants were resolved and checked by checkGrants; a dry run
// writes nothing, and the changes it would make are already reported on
// the role's `~` line.
func (a *applier) applyRolePermissions(prog *Program) error {
	if a.dryRun {
		return nil
	}
	for _, r := range prog.Roles {
		if !grantsManaged(r) {
			continue
		}
		// Re-fetch the role to get its ID (just-created or pre-existing).
		stored, err := a.store.GetRoleBySlug(a.ctx, a.tenantID, r.NamespacePath, r.Slug)
		if err != nil || stored == nil {
			return fmt.Errorf("role %s not found after apply: %w", r.Slug, err)
		}
		refs, diags := a.desiredGrants(r)
		if len(diags) > 0 {
			return &DiagnosticError{Diags: diags}
		}
		if err := a.store.SetRolePermissions(a.ctx, a.tenantID, stored.ID, refs); err != nil {
			return fmt.Errorf("set permissions for role %s: %w", r.Slug, err)
		}
	}
	return nil
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
			Subjects:      policySubjects(p.Subjects),
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
		desired.Metadata = existing.Metadata
		desired.AppID = a.appFor(existing.AppID)
		changed := policyChanges(existing, desired)
		if len(changed) == 0 {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, updateLine("policy", p.NamespacePath, p.Name, changed))
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

// policySubjects converts a policy's subject matchers for storage.
func policySubjects(in []*SubjectMatchDecl) []policy.SubjectMatch {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.SubjectMatch, 0, len(in))
	for _, m := range in {
		out = append(out, policy.SubjectMatch{Kind: m.Kind, ID: m.ID, Role: m.Role})
	}
	return out
}

// policyChanges lists the fields of a policy that differ, in the words the
// language uses for them.
func policyChanges(a, b *policy.Policy) []string {
	var out []string
	if a.Description != b.Description {
		out = append(out, "description")
	}
	if a.Effect != b.Effect {
		out = append(out, "effect")
	}
	if a.Priority != b.Priority {
		out = append(out, "priority")
	}
	if a.IsActive != b.IsActive {
		out = append(out, "active")
	}
	if !timePtrEqual(a.NotBefore, b.NotBefore) {
		out = append(out, "not_before")
	}
	if !timePtrEqual(a.NotAfter, b.NotAfter) {
		out = append(out, "not_after")
	}
	if !stringsEqual(a.Obligations, b.Obligations) {
		out = append(out, "obligations")
	}
	if !subjectsEqual(a.Subjects, b.Subjects) {
		out = append(out, "subjects")
	}
	if !stringsEqual(a.Actions, b.Actions) {
		out = append(out, "actions")
	}
	if !stringsEqual(a.Resources, b.Resources) {
		out = append(out, "resources")
	}
	if !conditionsEqual(a.Conditions, b.Conditions) {
		out = append(out, "conditions")
	}
	if a.AppID != b.AppID {
		out = append(out, "app")
	}
	return out
}

// subjectsEqual compares two matcher lists in order; nil and empty are the
// same list.
func subjectsEqual(a, b []policy.SubjectMatch) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// conditionsEqual compares two condition lists in order, ids aside.
func conditionsEqual(a, b []policy.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Field != b[i].Field || a[i].Operator != b[i].Operator {
			return false
		}
		if !valuesEqual(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

// valuesEqual compares two condition values by what they say, not how the
// store typed them: every number compares as a float64 (the store's JSON
// gives float64, the parser gives int), and a []string equals a []any of
// the same strings.
func valuesEqual(a, b any) bool {
	return reflect.DeepEqual(normalizeValue(a), normalizeValue(b))
}

func normalizeValue(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int8:
		return float64(x)
	case int16:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case uint:
		return float64(x)
	case uint8:
		return float64(x)
	case uint16:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case float32:
		return float64(x)
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeValue(e)
		}
		return out
	}
	return v
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

// flattenConditions turns the program's conditions into the store's flat
// list, where every condition must hold. It is faithful for every shape
// Resolve accepts (checkConditions): atomic conditions without `negate`,
// `all_of` at any depth, and an `any_of` with exactly one condition. Apply
// resolves first, so no other shape reaches it.
func flattenConditions(in []*Condition) []policy.Condition {
	var out []policy.Condition
	var walk func(c *Condition)
	walk = func(c *Condition) {
		switch {
		case c.AnyOf != nil:
			if len(c.AnyOf) == 1 {
				walk(c.AnyOf[0])
			}
		case c.AllOf != nil:
			for _, inner := range c.AllOf {
				walk(inner)
			}
		case c.Field != "":
			out = append(out, policy.Condition{
				ID:       id.NewConditionID(),
				Field:    c.Field,
				Operator: policy.Operator(c.Operator),
				Value:    c.Value,
			})
		}
	}
	for _, c := range in {
		walk(c)
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
