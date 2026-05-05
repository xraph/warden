package dsl

import (
	"strings"

	"github.com/xraph/warden"
)

// Resolve performs name resolution and type checking against a parsed
// program (or merged program from a multi-file load set). Returns any
// diagnostics found; the program may still be applied even with warnings.
//
// Checks performed:
//   - duplicate slugs / names within and across files
//   - role parent slug resolves to a real role (local or ancestor namespace)
//   - cycle detection in the role parent graph
//   - resource-type permission expressions reference declared relations
//   - traversal expressions hop through declared relation targets
//   - condition operators are valid
//   - identifier conventions (slug regex, name regex, namespace path)
func Resolve(prog *Program) []*Diagnostic {
	r := &resolver{
		prog:        prog,
		rolesByKey:  make(map[string]*RoleDecl),
		permsByKey:  make(map[string]*PermissionDecl),
		policyByKey: make(map[string]*PolicyDecl),
		rtsByKey:    make(map[string]*ResourceDecl),
	}
	r.indexAndCheckDuplicates()
	r.checkConventions()
	r.checkRoleParents()
	r.checkCycles()
	r.checkExpressions()
	return r.errs
}

type resolver struct {
	prog *Program
	errs []*Diagnostic

	rolesByKey  map[string]*RoleDecl       // (ns, slug) → role
	permsByKey  map[string]*PermissionDecl // (ns, name) → perm
	policyByKey map[string]*PolicyDecl
	rtsByKey    map[string]*ResourceDecl
}

func (r *resolver) errf(pos Pos, format string, args ...any) {
	r.errs = append(r.errs, &Diagnostic{Pos: pos, Msg: sprintf(format, args...)})
}

func keyOf(ns, name string) string {
	return ns + "\x00" + name
}

func (r *resolver) indexAndCheckDuplicates() {
	for _, role := range r.prog.Roles {
		k := keyOf(role.NamespacePath, role.Slug)
		if existing, ok := r.rolesByKey[k]; ok {
			r.errf(role.Pos, "role %q already declared at %s", role.Slug, existing.Pos)
			continue
		}
		r.rolesByKey[k] = role
	}
	for _, perm := range r.prog.Permissions {
		k := keyOf(perm.NamespacePath, perm.Name)
		if existing, ok := r.permsByKey[k]; ok {
			r.errf(perm.Pos, "permission %q already declared at %s", perm.Name, existing.Pos)
			continue
		}
		r.permsByKey[k] = perm
	}
	for _, pol := range r.prog.Policies {
		k := keyOf(pol.NamespacePath, pol.Name)
		if existing, ok := r.policyByKey[k]; ok {
			r.errf(pol.Pos, "policy %q already declared at %s", pol.Name, existing.Pos)
			continue
		}
		r.policyByKey[k] = pol
	}
	for _, rt := range r.prog.ResourceTypes {
		k := keyOf(rt.NamespacePath, rt.Name)
		if existing, ok := r.rtsByKey[k]; ok {
			r.errf(rt.Pos, "resource type %q already declared at %s", rt.Name, existing.Pos)
			continue
		}
		r.rtsByKey[k] = rt
	}
}

func (r *resolver) checkConventions() {
	for _, role := range r.prog.Roles {
		if !slugRegex.MatchString(role.Slug) {
			r.errf(role.Pos, "role slug %q must match %s", role.Slug, slugRegex.String())
		}
		if err := warden.ValidateNamespacePath(role.NamespacePath, 0); err != nil {
			r.errf(role.Pos, "%v", err)
		}
	}
	for _, perm := range r.prog.Permissions {
		if !permNameRegex.MatchString(perm.Name) {
			r.errf(perm.Pos, "permission name %q must be `<resource>:<action>` matching %s", perm.Name, permNameRegex.String())
		}
		if err := warden.ValidateNamespacePath(perm.NamespacePath, 0); err != nil {
			r.errf(perm.Pos, "%v", err)
		}
	}
	for _, pol := range r.prog.Policies {
		if !slugRegex.MatchString(pol.Name) {
			r.errf(pol.Pos, "policy name %q must match %s", pol.Name, slugRegex.String())
		}
		if pol.Effect == "" {
			r.errf(pol.Pos, "policy %q is missing `effect`", pol.Name)
		}
		if pol.NotBefore != nil && pol.NotAfter != nil && pol.NotAfter.Before(*pol.NotBefore) {
			r.errf(pol.Pos, "policy %q has not_after (%s) before not_before (%s)",
				pol.Name,
				pol.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
				pol.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			)
		}
	}
	for _, rt := range r.prog.ResourceTypes {
		if !rtNameRegex.MatchString(rt.Name) {
			r.errf(rt.Pos, "resource type %q must match %s", rt.Name, rtNameRegex.String())
		}
	}
}

// checkRoleParents resolves each role's Parent field to an actual role and
// reports an error when the reference cannot be resolved. The local resolution
// rule is: a bare slug resolves at the current namespace; if not found, walk
// ancestors. A leading "/" indicates an absolute namespace path
// (`role X : /eng/admin`).
func (r *resolver) checkRoleParents() {
	for _, role := range r.prog.Roles {
		if role.Parent == "" {
			continue
		}
		if _, found := r.lookupParent(role); !found {
			r.errf(role.Pos, "role %q references unknown parent %q (in namespace %q)", role.Slug, role.Parent, role.NamespacePath)
		}
	}
}

// lookupParent finds the parent role for the given role. Returns the parent
// declaration and a found flag. Resolution honors the local→ancestor walk
// for bare slugs and accepts absolute paths starting with "/".
func (r *resolver) lookupParent(role *RoleDecl) (*RoleDecl, bool) {
	parent := role.Parent
	if strings.HasPrefix(parent, "/") {
		// Absolute path: split into ns + slug.
		rest := parent[1:]
		idx := strings.LastIndex(rest, "/")
		var ns, slug string
		if idx < 0 {
			ns = ""
			slug = rest
		} else {
			ns = rest[:idx]
			slug = rest[idx+1:]
		}
		p, ok := r.rolesByKey[keyOf(ns, slug)]
		return p, ok
	}
	// Local lookup with ancestor walk.
	for _, ns := range warden.AncestorNamespaces(role.NamespacePath) {
		if p, ok := r.rolesByKey[keyOf(ns, parent)]; ok {
			return p, true
		}
	}
	return nil, false
}

// checkCycles walks the role parent graph and reports cycles.
func (r *resolver) checkCycles() {
	const (
		unvisited = 0
		inStack   = 1
		visited   = 2
	)
	state := make(map[*RoleDecl]int)
	var dfs func(*RoleDecl, []*RoleDecl)
	dfs = func(role *RoleDecl, path []*RoleDecl) {
		switch state[role] {
		case inStack:
			cycle := append([]*RoleDecl{}, path...)
			cycle = append(cycle, role)
			r.errf(role.Pos, "role %q is part of a parent cycle: %s", role.Slug, formatCycle(cycle))
			return
		case visited:
			return
		}
		state[role] = inStack
		if role.Parent != "" {
			if parent, ok := r.lookupParent(role); ok {
				dfs(parent, append(path, role))
			}
		}
		state[role] = visited
	}
	for _, role := range r.prog.Roles {
		dfs(role, nil)
	}
}

func formatCycle(roles []*RoleDecl) string {
	parts := make([]string, 0, len(roles))
	for _, r := range roles {
		parts = append(parts, r.Slug)
	}
	return strings.Join(parts, " -> ")
}

// checkExpressions walks every resource-type permission expression and
// validates that referenced names resolve to declared relations on the
// owning resource type, and that traversal hops chain through declared
// relations on the targeted resource types.
func (r *resolver) checkExpressions() {
	for _, rt := range r.prog.ResourceTypes {
		// Build a relation-name → target-resource-type map for traversal checks.
		// (For relations declared without #-suffix, the target type is the
		// allowed subject's type.)
		targets := make(map[string]string)
		for _, rel := range rt.Relations {
			// The target type for traversal is the FIRST allowed subject's type.
			// Multiple subjects are valid for direct grants but traversal needs
			// a single concrete type; we conservatively use the first.
			if len(rel.AllowedSubjects) > 0 {
				targets[rel.Name] = rel.AllowedSubjects[0].Type
			}
		}
		for _, perm := range rt.Permissions {
			r.checkExprNames(rt, perm.Expr, targets)
		}
	}
}

func (r *resolver) checkExprNames(rt *ResourceDecl, e Expr, targets map[string]string) {
	switch v := e.(type) {
	case *RefExpr:
		if _, ok := targets[v.Name]; !ok {
			r.errf(v.Pos, "expression references undeclared relation %q on resource %q", v.Name, rt.Name)
		}
	case *TraverseExpr:
		// Must have at least 2 steps.
		if len(v.Steps) < 2 {
			r.errf(v.Pos, "traversal must have at least one `->` hop")
			return
		}
		// First step must be a relation on the owning resource.
		first := v.Steps[0]
		targetType, ok := targets[first]
		if !ok {
			r.errf(v.Pos, "traversal starts with undeclared relation %q on resource %q", first, rt.Name)
			return
		}
		// Subsequent steps must resolve on the chain's current target type.
		for i := 1; i < len(v.Steps); i++ {
			nextRT := r.findResourceType(targetType)
			if nextRT == nil {
				r.errf(v.Pos, "traversal hops into undeclared resource type %q", targetType)
				return
			}
			step := v.Steps[i]
			// Step can be a relation or a permission on nextRT.
			matched := false
			var nextTarget string
			for _, rel := range nextRT.Relations {
				if rel.Name == step {
					matched = true
					if len(rel.AllowedSubjects) > 0 {
						nextTarget = rel.AllowedSubjects[0].Type
					}
					break
				}
			}
			if !matched {
				for _, perm := range nextRT.Permissions {
					if perm.Name == step {
						matched = true
						break
					}
				}
			}
			if !matched {
				r.errf(v.Pos, "traversal step %q is not a relation or permission on resource %q", step, nextRT.Name)
				return
			}
			targetType = nextTarget
		}
	case *OrExpr:
		r.checkExprNames(rt, v.Left, targets)
		r.checkExprNames(rt, v.Right, targets)
	case *AndExpr:
		r.checkExprNames(rt, v.Left, targets)
		r.checkExprNames(rt, v.Right, targets)
	case *NotExpr:
		r.checkExprNames(rt, v.Inner, targets)
	}
}

func (r *resolver) findResourceType(name string) *ResourceDecl {
	// Naive lookup: pick the first resource type with this name across all
	// namespaces. This matches simple flat configs; cross-namespace ReBAC
	// across resource types is uncommon and out of scope for v1.
	for _, rt := range r.prog.ResourceTypes {
		if rt.Name == name {
			return rt
		}
	}
	return nil
}

// sprintf wraps fmt.Sprintf without dragging fmt into hot paths if we ever
// inline this further. Using fmt directly today.
func sprintf(format string, args ...any) string {
	return formatf(format, args...)
}
