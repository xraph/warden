package dsl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xraph/warden"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// Layout controls how `warden export` distributes a tenant's state across
// .warden files.
type Layout int

const (
	// FlatLayout writes everything to a single main.warden file.
	FlatLayout Layout = iota
	// SectionalLayout splits by entity kind: 00-resource-types.warden,
	// 10-permissions.warden, 20-roles.warden, 30-policies.warden,
	// 40-relations.warden.
	SectionalLayout
	// DomainLayout groups by namespace path. Each top-level segment becomes
	// a directory; entities at the tenant root go to a `_root/` directory.
	DomainLayout
)

// ExportOptions configures Export.
type ExportOptions struct {
	// TenantID is required — the tenant whose state is exported.
	TenantID string
	// AppID is optional and propagates to the emitted header.
	AppID string
	// NamespacePrefix limits the export to entities whose namespace_path
	// equals or descends from this value. Empty means "all namespaces".
	NamespacePrefix string
	// Layout controls file layout (see Layout consts).
	Layout Layout
	// OutputDir is the destination root. Created if missing.
	OutputDir string
	// Now is unused at the moment; reserved for header generation timestamps.
}

// Export reads tenant state from the engine's store and writes .warden
// source to opts.OutputDir according to the chosen Layout. It returns the
// number of files written.
//
// The output is canonical (passes through Format), so apply(export(state))
// produces zero diff against the original state.
func Export(ctx context.Context, eng *warden.Engine, opts ExportOptions) (int, error) {
	if opts.TenantID == "" {
		return 0, fmt.Errorf("warden export: TenantID is required")
	}
	if opts.OutputDir == "" {
		return 0, fmt.Errorf("warden export: OutputDir is required")
	}
	if err := os.MkdirAll(opts.OutputDir, 0o750); err != nil {
		return 0, fmt.Errorf("warden export: mkdir: %w", err)
	}

	prog, err := BuildProgram(ctx, eng, opts)
	if err != nil {
		return 0, err
	}

	switch opts.Layout {
	case FlatLayout:
		return writeFlat(opts.OutputDir, prog)
	case SectionalLayout:
		return writeSectional(opts.OutputDir, prog)
	case DomainLayout:
		return writeDomain(opts.OutputDir, prog)
	default:
		return 0, fmt.Errorf("warden export: unknown layout %d", opts.Layout)
	}
}

// BuildProgram reads tenant state and constructs an in-memory Program.
// Useful for tests that want to round-trip without writing to disk, and for
// custom emitters.
func BuildProgram(ctx context.Context, eng *warden.Engine, opts ExportOptions) (*Program, error) {
	store := eng.Store()
	prog := &Program{
		Version: 1,
		Tenant:  opts.TenantID,
		App:     opts.AppID,
	}

	prefix := opts.NamespacePrefix
	matches := func(ns string) bool {
		if prefix == "" {
			return true
		}
		return ns == prefix || strings.HasPrefix(ns, prefix+"/")
	}

	rts, err := store.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: opts.TenantID})
	if err != nil {
		return nil, fmt.Errorf("list resource types: %w", err)
	}
	for _, rt := range rts {
		if !matches(rt.NamespacePath) {
			continue
		}
		prog.ResourceTypes = append(prog.ResourceTypes, resourceTypeToDecl(rt))
	}

	perms, err := store.ListPermissions(ctx, &permission.ListFilter{TenantID: opts.TenantID})
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	for _, p := range perms {
		if !matches(p.NamespacePath) {
			continue
		}
		prog.Permissions = append(prog.Permissions, permissionToDecl(p))
	}

	roles, err := store.ListRoles(ctx, &role.ListFilter{TenantID: opts.TenantID})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	for _, r := range roles {
		if !matches(r.NamespacePath) {
			continue
		}
		decl := roleToDecl(r)
		// Phase A.5: ListRolePermissions returns full Permission records.
		grantPerms, gpErr := store.ListRolePermissions(ctx, r.ID)
		if gpErr != nil {
			return nil, fmt.Errorf("list grants for role %s: %w", r.Slug, gpErr)
		}
		grants := make([]string, 0, len(grantPerms))
		for _, p := range grantPerms {
			grants = append(grants, p.Name)
		}
		sort.Strings(grants)
		decl.Grants = grants
		prog.Roles = append(prog.Roles, decl)
	}

	policies, err := store.ListPolicies(ctx, &policy.ListFilter{TenantID: opts.TenantID})
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	for _, p := range policies {
		if !matches(p.NamespacePath) {
			continue
		}
		prog.Policies = append(prog.Policies, policyToDecl(p))
	}

	tuples, err := store.ListRelations(ctx, &relation.ListFilter{TenantID: opts.TenantID})
	if err != nil {
		return nil, fmt.Errorf("list relations: %w", err)
	}
	for _, t := range tuples {
		if !matches(t.NamespacePath) {
			continue
		}
		prog.Relations = append(prog.Relations, tupleToDecl(t))
	}

	return prog, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Layout writers.
// ─────────────────────────────────────────────────────────────────────────

func writeFlat(dir string, prog *Program) (int, error) {
	src := Format(prog)
	path := filepath.Join(dir, "main.warden")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		return 0, err
	}
	return 1, nil
}

func writeSectional(dir string, prog *Program) (int, error) {
	files := []struct {
		name string
		mod  func(*Program) *Program
	}{
		{"00-resource-types.warden", func(p *Program) *Program {
			return &Program{Version: p.Version, Tenant: p.Tenant, App: p.App, ResourceTypes: p.ResourceTypes}
		}},
		{"10-permissions.warden", func(p *Program) *Program {
			return &Program{Version: p.Version, Tenant: p.Tenant, Permissions: p.Permissions}
		}},
		{"20-roles.warden", func(p *Program) *Program {
			return &Program{Version: p.Version, Tenant: p.Tenant, Roles: p.Roles}
		}},
		{"30-policies.warden", func(p *Program) *Program {
			return &Program{Version: p.Version, Tenant: p.Tenant, Policies: p.Policies}
		}},
		{"40-relations.warden", func(p *Program) *Program {
			return &Program{Version: p.Version, Tenant: p.Tenant, Relations: p.Relations}
		}},
	}
	count := 0
	for _, f := range files {
		section := f.mod(prog)
		// Skip empty sections.
		if len(section.ResourceTypes)+len(section.Permissions)+len(section.Roles)+len(section.Policies)+len(section.Relations) == 0 {
			continue
		}
		src := Format(section)
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(src), 0o600); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func writeDomain(dir string, prog *Program) (int, error) {
	// Group decls by top-level namespace segment. Empty namespace → "_root".
	groups := make(map[string]*Program)
	groupFor := func(ns string) *Program {
		key := domainKey(ns)
		if g, ok := groups[key]; ok {
			return g
		}
		g := &Program{Version: prog.Version, Tenant: prog.Tenant, App: prog.App}
		groups[key] = g
		return g
	}
	for _, rt := range prog.ResourceTypes {
		groupFor(rt.NamespacePath).ResourceTypes = append(groupFor(rt.NamespacePath).ResourceTypes, rt)
	}
	for _, p := range prog.Permissions {
		groupFor(p.NamespacePath).Permissions = append(groupFor(p.NamespacePath).Permissions, p)
	}
	for _, r := range prog.Roles {
		groupFor(r.NamespacePath).Roles = append(groupFor(r.NamespacePath).Roles, r)
	}
	for _, p := range prog.Policies {
		groupFor(p.NamespacePath).Policies = append(groupFor(p.NamespacePath).Policies, p)
	}
	for _, t := range prog.Relations {
		groupFor(t.NamespacePath).Relations = append(groupFor(t.NamespacePath).Relations, t)
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	count := 0
	for _, k := range keys {
		g := groups[k]
		subdir := filepath.Join(dir, k)
		if err := os.MkdirAll(subdir, 0o750); err != nil {
			return count, err
		}
		path := filepath.Join(subdir, "main.warden")
		if err := os.WriteFile(path, []byte(Format(g)), 0o600); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func domainKey(ns string) string {
	if ns == "" {
		return "_root"
	}
	if i := strings.Index(ns, "/"); i >= 0 {
		return ns[:i]
	}
	return ns
}

// ─────────────────────────────────────────────────────────────────────────
// Domain → DSL decl converters.
// ─────────────────────────────────────────────────────────────────────────

func resourceTypeToDecl(rt *resourcetype.ResourceType) *ResourceDecl {
	d := &ResourceDecl{
		Name:          rt.Name,
		NamespacePath: rt.NamespacePath,
		Description:   rt.Description,
	}
	for _, rel := range rt.Relations {
		def := &RelationDef{Name: rel.Name}
		for _, sub := range rel.AllowedSubjects {
			st := SubjectType{Type: sub}
			if before, after, ok := strings.Cut(sub, "#"); ok {
				st.Type = before
				st.Relation = after
			}
			def.AllowedSubjects = append(def.AllowedSubjects, st)
		}
		d.Relations = append(d.Relations, def)
	}
	for _, p := range rt.Permissions {
		expr, errs := CompileExpr("<exported>", p.Expression)
		if len(errs) > 0 {
			// Fall back to a Ref placeholder so the export at least round-trips
			// the name; reviewers will see the un-parsed expression as text.
			expr = &RefExpr{Name: p.Expression}
		}
		d.Permissions = append(d.Permissions, &ResourcePermissionDecl{Name: p.Name, Expr: expr})
	}
	return d
}

func permissionToDecl(p *permission.Permission) *PermissionDecl {
	return &PermissionDecl{
		Name:          p.Name,
		NamespacePath: p.NamespacePath,
		Description:   p.Description,
		Resource:      p.Resource,
		Action:        p.Action,
		IsSystem:      p.IsSystem,
	}
}

func roleToDecl(r *role.Role) *RoleDecl {
	return &RoleDecl{
		Slug:          r.Slug,
		NamespacePath: r.NamespacePath,
		Parent:        r.ParentSlug,
		Name:          r.Name,
		Description:   r.Description,
		IsSystem:      r.IsSystem,
		IsDefault:     r.IsDefault,
		MaxMembers:    r.MaxMembers,
	}
}

func policyToDecl(p *policy.Policy) *PolicyDecl {
	d := &PolicyDecl{
		Name:          p.Name,
		NamespacePath: p.NamespacePath,
		Description:   p.Description,
		Effect:        string(p.Effect),
		Priority:      p.Priority,
		Active:        p.IsActive,
		NotBefore:     p.NotBefore,
		NotAfter:      p.NotAfter,
		Obligations:   append([]string{}, p.Obligations...),
		Actions:       append([]string{}, p.Actions...),
		Resources:     append([]string{}, p.Resources...),
	}
	for _, c := range p.Conditions {
		d.Conditions = append(d.Conditions, &Condition{
			Field:    c.Field,
			Operator: string(c.Operator),
			Value:    c.Value,
		})
	}
	return d
}

func tupleToDecl(t *relation.Tuple) *RelationDecl {
	return &RelationDecl{
		NamespacePath:   t.NamespacePath,
		ObjectType:      t.ObjectType,
		ObjectID:        t.ObjectID,
		Relation:        t.Relation,
		SubjectType:     t.SubjectType,
		SubjectID:       t.SubjectID,
		SubjectRelation: t.SubjectRelation,
	}
}
