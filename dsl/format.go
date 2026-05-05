package dsl

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Format renders a Program back to canonical .warden source. The output is
// stable: parsing then formatting again yields the same bytes.
//
// Canonical rules (see plan section D.1.a):
//   - 4-space indent; LF line endings; final newline.
//   - One blank line between top-level decls; two between section dividers.
//   - Decls within a section sorted by name/slug for stability.
//   - Within blocks, fields ordered (name, description, flags…, grants/when last).
//   - Permission expressions rendered with parens elided where precedence permits.
//   - Multi-line string lists when len > 3, inline otherwise.
func Format(prog *Program) string {
	if prog == nil {
		return ""
	}
	f := &formatter{}
	f.program(prog)
	out := f.buf.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

// FormatBytes is a byte-slice convenience wrapper around Format.
func FormatBytes(prog *Program) []byte {
	return []byte(Format(prog))
}

type formatter struct {
	buf    bytes.Buffer
	indent int
}

func (f *formatter) writeIndent() {
	for i := 0; i < f.indent; i++ {
		f.buf.WriteString("    ")
	}
}

func (f *formatter) writef(format string, args ...any) {
	f.writeIndent()
	fmt.Fprintf(&f.buf, format, args...)
}

func (f *formatter) writeln(s string) {
	f.writeIndent()
	f.buf.WriteString(s)
	f.buf.WriteByte('\n')
}

func (f *formatter) blank() {
	f.buf.WriteByte('\n')
}

func (f *formatter) program(prog *Program) {
	// Header.
	if prog.Version > 0 {
		f.writef("warden config %d\n", prog.Version)
	} else {
		f.writeln("warden config 1")
	}
	if prog.Tenant != "" {
		f.writef("tenant %s\n", prog.Tenant)
	}
	if prog.App != "" {
		f.writef("app %s\n", prog.App)
	}
	f.blank()

	// Sections in canonical order. Two blank lines between sections.
	sections := []struct {
		name  string
		emit  func()
		count int
	}{
		{"resource_types", func() { f.resourceTypes(prog.ResourceTypes) }, len(prog.ResourceTypes)},
		{"permissions", func() { f.permissions(prog.Permissions) }, len(prog.Permissions)},
		{"roles", func() { f.roles(prog.Roles) }, len(prog.Roles)},
		{"policies", func() { f.policies(prog.Policies) }, len(prog.Policies)},
		{"relations", func() { f.relations(prog.Relations) }, len(prog.Relations)},
	}
	first := true
	for _, sec := range sections {
		if sec.count == 0 {
			continue
		}
		if !first {
			f.blank()
		}
		first = false
		sec.emit()
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Resource types.
// ─────────────────────────────────────────────────────────────────────────

func (f *formatter) resourceTypes(rts []*ResourceDecl) {
	sorted := append([]*ResourceDecl{}, rts...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].NamespacePath != sorted[j].NamespacePath {
			return sorted[i].NamespacePath < sorted[j].NamespacePath
		}
		return sorted[i].Name < sorted[j].Name
	})
	for i, rt := range sorted {
		if i > 0 {
			f.blank()
		}
		f.resourceType(rt)
	}
}

func (f *formatter) resourceType(rt *ResourceDecl) {
	f.writef("resource %s {\n", rt.Name)
	f.indent++
	if rt.Description != "" {
		f.writef("description = %s\n", strconv.Quote(rt.Description))
	}
	relations := append([]*RelationDef{}, rt.Relations...)
	sort.Slice(relations, func(i, j int) bool { return relations[i].Name < relations[j].Name })
	for _, rel := range relations {
		f.relationDef(rel)
	}
	if len(relations) > 0 && len(rt.Permissions) > 0 {
		f.blank()
	}
	perms := append([]*ResourcePermissionDecl{}, rt.Permissions...)
	sort.Slice(perms, func(i, j int) bool { return perms[i].Name < perms[j].Name })
	for _, perm := range perms {
		f.writef("permission %s = %s\n", perm.Name, FormatExpr(perm.Expr))
	}
	f.indent--
	f.writeln("}")
}

func (f *formatter) relationDef(rel *RelationDef) {
	subjects := make([]string, 0, len(rel.AllowedSubjects))
	for _, s := range rel.AllowedSubjects {
		if s.Relation == "" {
			subjects = append(subjects, s.Type)
		} else {
			subjects = append(subjects, s.Type+"#"+s.Relation)
		}
	}
	f.writef("relation %s: %s\n", rel.Name, strings.Join(subjects, " | "))
}

// ─────────────────────────────────────────────────────────────────────────
// Permissions (top-level catalog).
// ─────────────────────────────────────────────────────────────────────────

func (f *formatter) permissions(perms []*PermissionDecl) {
	sorted := append([]*PermissionDecl{}, perms...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].NamespacePath != sorted[j].NamespacePath {
			return sorted[i].NamespacePath < sorted[j].NamespacePath
		}
		return sorted[i].Name < sorted[j].Name
	})
	for _, p := range sorted {
		// Compute padding so columns of related permissions align.
		f.writef("permission %s (%s : %s)\n",
			strconv.Quote(p.Name), p.Resource, p.Action)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Roles.
// ─────────────────────────────────────────────────────────────────────────

func (f *formatter) roles(roles []*RoleDecl) {
	sorted := append([]*RoleDecl{}, roles...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].NamespacePath != sorted[j].NamespacePath {
			return sorted[i].NamespacePath < sorted[j].NamespacePath
		}
		return sorted[i].Slug < sorted[j].Slug
	})
	for i, r := range sorted {
		if i > 0 {
			f.blank()
		}
		f.role(r)
	}
}

func (f *formatter) role(r *RoleDecl) {
	if r.Parent != "" {
		f.writef("role %s : %s {\n", r.Slug, r.Parent)
	} else {
		f.writef("role %s {\n", r.Slug)
	}
	f.indent++
	if r.Name != "" {
		f.writef("name = %s\n", strconv.Quote(r.Name))
	}
	if r.Description != "" {
		f.writef("description = %s\n", strconv.Quote(r.Description))
	}
	if r.IsSystem {
		f.writeln("is_system = true")
	}
	if r.IsDefault {
		f.writeln("is_default = true")
	}
	if r.MaxMembers != 0 {
		f.writef("max_members = %d\n", r.MaxMembers)
	}
	if len(r.Grants) > 0 {
		op := "="
		if r.GrantsAppend {
			op = "+="
		}
		f.writef("grants %s %s\n", op, formatStringList(r.Grants))
	}
	f.indent--
	f.writeln("}")
}

// ─────────────────────────────────────────────────────────────────────────
// Policies.
// ─────────────────────────────────────────────────────────────────────────

func (f *formatter) policies(policies []*PolicyDecl) {
	sorted := append([]*PolicyDecl{}, policies...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].NamespacePath != sorted[j].NamespacePath {
			return sorted[i].NamespacePath < sorted[j].NamespacePath
		}
		return sorted[i].Name < sorted[j].Name
	})
	for i, p := range sorted {
		if i > 0 {
			f.blank()
		}
		f.policy(p)
	}
}

func (f *formatter) policy(p *PolicyDecl) {
	f.writef("policy %s {\n", strconv.Quote(p.Name))
	f.indent++
	if p.Description != "" {
		f.writef("description = %s\n", strconv.Quote(p.Description))
	}
	if p.Effect != "" {
		f.writef("effect = %s\n", p.Effect)
	}
	if p.Priority != 0 {
		f.writef("priority = %d\n", p.Priority)
	}
	f.writef("active = %t\n", p.Active)
	if p.NotBefore != nil {
		f.writef("not_before = %s\n", strconv.Quote(p.NotBefore.UTC().Format(time.RFC3339Nano)))
	}
	if p.NotAfter != nil {
		f.writef("not_after = %s\n", strconv.Quote(p.NotAfter.UTC().Format(time.RFC3339Nano)))
	}
	if len(p.Obligations) > 0 {
		f.writef("obligations = %s\n", formatStringList(p.Obligations))
	}
	if len(p.Actions) > 0 {
		f.writef("actions = %s\n", formatStringList(p.Actions))
	}
	if len(p.Resources) > 0 {
		f.writef("resources = %s\n", formatStringList(p.Resources))
	}
	if len(p.Conditions) > 0 {
		f.writeln("when {")
		f.indent++
		for _, c := range p.Conditions {
			f.condition(c)
		}
		f.indent--
		f.writeln("}")
	}
	f.indent--
	f.writeln("}")
}

func (f *formatter) condition(c *Condition) {
	if len(c.AllOf) > 0 {
		f.writeln("all_of {")
		f.indent++
		for _, inner := range c.AllOf {
			f.condition(inner)
		}
		f.indent--
		f.writeln("}")
		return
	}
	if len(c.AnyOf) > 0 {
		f.writeln("any_of {")
		f.indent++
		for _, inner := range c.AnyOf {
			f.condition(inner)
		}
		f.indent--
		f.writeln("}")
		return
	}
	op := canonicalOp(c.Operator)
	val := formatLiteral(c.Value)
	suffix := ""
	if c.Negate {
		suffix = " negate"
	}
	f.writef("%s %s %s%s\n", c.Field, op, val, suffix)
}

// canonicalOp returns the source-form keyword spelling for a policy operator.
func canonicalOp(op string) string {
	switch op {
	case "eq":
		return "=="
	case "neq":
		return "!="
	case "gt":
		return ">"
	case "lt":
		return "<"
	case "gte":
		return ">="
	case "lte":
		return "<="
	case "regex":
		return "=~"
	case "not_in":
		return "not in"
	case "not_exists":
		return "not exists"
	default:
		return op
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Relations (initial state).
// ─────────────────────────────────────────────────────────────────────────

func (f *formatter) relations(relations []*RelationDecl) {
	sorted := append([]*RelationDecl{}, relations...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].NamespacePath != sorted[j].NamespacePath {
			return sorted[i].NamespacePath < sorted[j].NamespacePath
		}
		ai := sorted[i].ObjectType + ":" + sorted[i].ObjectID + "/" + sorted[i].Relation
		bj := sorted[j].ObjectType + ":" + sorted[j].ObjectID + "/" + sorted[j].Relation
		return ai < bj
	})
	for _, r := range sorted {
		subj := r.SubjectType + ":" + r.SubjectID
		if r.SubjectRelation != "" {
			subj += "#" + r.SubjectRelation
		}
		f.writef("relation %s:%s %s = %s\n",
			r.ObjectType, r.ObjectID, r.Relation, subj)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

// formatStringList renders []string canonically: inline for ≤ 3 items,
// multi-line with trailing comma otherwise.
func formatStringList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	if len(items) <= 3 {
		quoted := make([]string, len(items))
		for i, it := range items {
			quoted[i] = strconv.Quote(it)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for _, it := range items {
		b.WriteString("    ")
		b.WriteString(strconv.Quote(it))
		b.WriteString(",\n")
	}
	b.WriteString("]")
	return b.String()
}

// formatLiteral renders a condition value. Falls back to fmt.Sprint for
// types we don't special-case.
func formatLiteral(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case []string:
		return formatStringList(x)
	case []any:
		strs := make([]string, len(x))
		for i, e := range x {
			strs[i] = formatLiteral(e)
		}
		return "[" + strings.Join(strs, ", ") + "]"
	case nil:
		return "null"
	}
	return strconv.Quote(fmt.Sprintf("%v", v))
}
