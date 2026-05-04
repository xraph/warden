package dsl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

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
func Apply(ctx context.Context, eng *warden.Engine, prog *Program, opts ApplyOptions) (*ApplyResult, error) {
	tenantID := firstNonEmpty(opts.TenantID, prog.Tenant)
	if tenantID == "" {
		return nil, fmt.Errorf("warden dsl: tenant ID is required (set via opts.TenantID or `tenant <id>` in source)")
	}
	if errs := Resolve(prog); len(errs) > 0 {
		return nil, &diagnosticError{errs: errs}
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
	ctx      context.Context
	eng      *warden.Engine
	store    interface {
		// Roles
		CreateRole(ctx context.Context, r *role.Role) error
		GetRoleBySlug(ctx context.Context, tenantID, slug string) (*role.Role, error)
		UpdateRole(ctx context.Context, r *role.Role) error
		DeleteRole(ctx context.Context, roleID id.RoleID) error
		ListRoles(ctx context.Context, filter *role.ListFilter) ([]*role.Role, error)
		// Permissions
		CreatePermission(ctx context.Context, p *permission.Permission) error
		GetPermissionByName(ctx context.Context, tenantID, name string) (*permission.Permission, error)
		UpdatePermission(ctx context.Context, p *permission.Permission) error
		DeletePermission(ctx context.Context, permID id.PermissionID) error
		ListPermissions(ctx context.Context, filter *permission.ListFilter) ([]*permission.Permission, error)
		SetRolePermissions(ctx context.Context, roleID id.RoleID, permIDs []id.PermissionID) error
		// Policies
		CreatePolicy(ctx context.Context, p *policy.Policy) error
		GetPolicyByName(ctx context.Context, tenantID, name string) (*policy.Policy, error)
		UpdatePolicy(ctx context.Context, p *policy.Policy) error
		DeletePolicy(ctx context.Context, polID id.PolicyID) error
		ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error)
		// Resource types
		CreateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error
		GetResourceTypeByName(ctx context.Context, tenantID, name string) (*resourcetype.ResourceType, error)
		UpdateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error
		DeleteResourceType(ctx context.Context, rtID id.ResourceTypeID) error
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

	result *ApplyResult
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
	if err := a.applyRelations(prog); err != nil {
		return err
	}
	return nil
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
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetResourceTypeByName(a.ctx, a.tenantID, rt.Name)
		if existing == nil {
			desired.ID = id.NewResourceTypeID()
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ resource_type/%s/%s", rt.NamespacePath, rt.Name))
			if !a.dryRun {
				if err := a.store.CreateResourceType(a.ctx, desired); err != nil {
					return fmt.Errorf("create resource type %s: %w", rt.Name, err)
				}
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		if rtEquivalent(existing, desired) {
			a.result.NoOps++
			continue
		}
		a.result.Updated = append(a.result.Updated, fmt.Sprintf("~ resource_type/%s/%s", rt.NamespacePath, rt.Name))
		if !a.dryRun {
			if err := a.store.UpdateResourceType(a.ctx, desired); err != nil {
				return fmt.Errorf("update resource type %s: %w", rt.Name, err)
			}
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
	existing, err := a.store.ListResourceTypes(a.ctx, &resourcetype.ListFilter{TenantID: a.tenantID})
	if err != nil {
		return err
	}
	for _, rt := range existing {
		if _, ok := declared[keyOf(rt.NamespacePath, rt.Name)]; ok {
			continue
		}
		a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- resource_type/%s/%s", rt.NamespacePath, rt.Name))
		if !a.dryRun {
			if err := a.store.DeleteResourceType(a.ctx, rt.ID); err != nil {
				return fmt.Errorf("delete resource type %s: %w", rt.Name, err)
			}
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
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetPermissionByName(a.ctx, a.tenantID, p.Name)
		if existing == nil {
			desired.ID = id.NewPermissionID()
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ permission/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.CreatePermission(a.ctx, desired); err != nil {
					return fmt.Errorf("create permission %s: %w", p.Name, err)
				}
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
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
		}
	}
	if a.prune {
		existing, err := a.store.ListPermissions(a.ctx, &permission.ListFilter{TenantID: a.tenantID})
		if err != nil {
			return err
		}
		for _, p := range existing {
			if _, ok := declared[keyOf(p.NamespacePath, p.Name)]; ok {
				continue
			}
			a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- permission/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.DeletePermission(a.ctx, p.ID); err != nil {
					return fmt.Errorf("delete permission %s: %w", p.Name, err)
				}
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
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetRoleBySlug(a.ctx, a.tenantID, r.Slug)
		if existing == nil {
			desired.ID = id.NewRoleID()
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ role/%s/%s", r.NamespacePath, r.Slug))
			if !a.dryRun {
				if err := a.store.CreateRole(a.ctx, desired); err != nil {
					return fmt.Errorf("create role %s: %w", r.Slug, err)
				}
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
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
		}
	}
	if a.prune {
		existing, err := a.store.ListRoles(a.ctx, &role.ListFilter{TenantID: a.tenantID})
		if err != nil {
			return err
		}
		for _, r := range existing {
			if _, ok := declared[keyOf(r.NamespacePath, r.Slug)]; ok {
				continue
			}
			if r.IsSystem {
				continue // system roles are protected from prune
			}
			a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- role/%s/%s", r.NamespacePath, r.Slug))
			if !a.dryRun {
				if err := a.store.DeleteRole(a.ctx, r.ID); err != nil {
					return fmt.Errorf("delete role %s: %w", r.Slug, err)
				}
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
// store yet (we skipped the writes), so we can only validate that every
// grant references a name that's also being declared in the same program.
func (a *applier) applyRolePermissions(prog *Program) error {
	if a.dryRun {
		// Build a set of declared permission names so we can sanity-check
		// grant references without touching the store.
		declared := make(map[string]struct{}, len(prog.Permissions))
		for _, p := range prog.Permissions {
			declared[p.Name] = struct{}{}
		}
		for _, r := range prog.Roles {
			for _, name := range r.Grants {
				if _, ok := declared[name]; ok {
					continue
				}
				if isGlob(name) {
					continue
				}
				// Fall back to checking the store — the perm may already exist.
				if perm, err := a.store.GetPermissionByName(a.ctx, a.tenantID, name); err == nil && perm != nil {
					continue
				}
				return fmt.Errorf("role %s grants unknown permission %q", r.Slug, name)
			}
		}
		return nil
	}

	for _, r := range prog.Roles {
		if len(r.Grants) == 0 && !r.GrantsAppend {
			continue
		}
		// Re-fetch the role to get its ID (just-created or pre-existing).
		stored, err := a.store.GetRoleBySlug(a.ctx, a.tenantID, r.Slug)
		if err != nil || stored == nil {
			return fmt.Errorf("role %s not found after apply: %v", r.Slug, err)
		}
		permIDs := make([]id.PermissionID, 0, len(r.Grants))
		for _, name := range r.Grants {
			perm, err := a.store.GetPermissionByName(a.ctx, a.tenantID, name)
			if err != nil || perm == nil {
				if isGlob(name) {
					// Glob permissions are matched at Check time without a
					// concrete attachment row. Skip.
					continue
				}
				return fmt.Errorf("role %s grants unknown permission %q", r.Slug, name)
			}
			permIDs = append(permIDs, perm.ID)
		}
		if err := a.store.SetRolePermissions(a.ctx, stored.ID, permIDs); err != nil {
			return fmt.Errorf("set permissions for role %s: %w", r.Slug, err)
		}
	}
	return nil
}

func isGlob(name string) bool {
	return strings.Contains(name, "*")
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
			Version:       1,
			Actions:       p.Actions,
			Resources:     p.Resources,
			Conditions:    flattenConditions(p.Conditions),
			CreatedAt:     a.now,
			UpdatedAt:     a.now,
		}
		existing, _ := a.store.GetPolicyByName(a.ctx, a.tenantID, p.Name)
		if existing == nil {
			desired.ID = id.NewPolicyID()
			a.result.Created = append(a.result.Created, fmt.Sprintf("+ policy/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.CreatePolicy(a.ctx, desired); err != nil {
					return fmt.Errorf("create policy %s: %w", p.Name, err)
				}
			}
			continue
		}
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
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
		}
	}
	if a.prune {
		existing, err := a.store.ListPolicies(a.ctx, &policy.ListFilter{TenantID: a.tenantID})
		if err != nil {
			return err
		}
		for _, p := range existing {
			if _, ok := declared[keyOf(p.NamespacePath, p.Name)]; ok {
				continue
			}
			a.result.Deleted = append(a.result.Deleted, fmt.Sprintf("- policy/%s/%s", p.NamespacePath, p.Name))
			if !a.dryRun {
				if err := a.store.DeletePolicy(a.ctx, p.ID); err != nil {
					return fmt.Errorf("delete policy %s: %w", p.Name, err)
				}
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
		t := &relation.Tuple{
			ID:              id.NewRelationID(),
			TenantID:        a.tenantID,
			NamespacePath:   r.NamespacePath,
			AppID:           a.appID,
			ObjectType:      r.ObjectType,
			ObjectID:        r.ObjectID,
			Relation:        r.Relation,
			SubjectType:     r.SubjectType,
			SubjectID:       r.SubjectID,
			SubjectRelation: r.SubjectRelation,
			CreatedAt:       a.now,
		}
		// Check if the tuple already exists.
		existing, _ := a.store.ListRelations(a.ctx, &relation.ListFilter{
			TenantID:        a.tenantID,
			NamespacePath:   nil, // exact-match below via SubjectRelation comparison
			ObjectType:      r.ObjectType,
			ObjectID:        r.ObjectID,
			Relation:        r.Relation,
			SubjectType:     r.SubjectType,
			SubjectID:       r.SubjectID,
			SubjectRelation: r.SubjectRelation,
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
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

// diagnosticError wraps a slice of resolver/parser diagnostics in an error.
type diagnosticError struct {
	errs []*Diagnostic
}

func (e *diagnosticError) Error() string {
	var b strings.Builder
	for i, d := range e.errs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(d.String())
	}
	return b.String()
}

// Diagnostics returns the underlying diagnostics for inspection.
func (e *diagnosticError) Diagnostics() []*Diagnostic { return e.errs }

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
