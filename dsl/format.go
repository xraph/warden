package dsl

import (
	"bytes"
	"fmt"
	"regexp"
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
//   - Entities at the tenant root first, then one `namespace "<path>" { ... }`
//     block per namespace path, sorted by path. Blocks are flat: a nested
//     namespace is written with its full path, not inside its parent.
//   - Within blocks, fields ordered (name, description, flags…, grants/when last).
//     Lists inside a block (relations, permissions, grants, subjects,
//     conditions) keep their order.
//   - Permission expressions rendered with parens elided where precedence permits.
//   - Multi-line string lists when len > 3, inline otherwise.
//   - A name a bare identifier cannot spell (a keyword, a leading digit, a
//     space, a colon, a glob) is written as a string literal.
//
// Format writes everything the language can express, so for a program
// built by BuildProgram, Parse(Format(prog)) applies back as a no-op.
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
		f.writef("tenant %s\n", formatName(prog.Tenant))
	}
	if prog.App != "" {
		f.writef("app %s\n", formatName(prog.App))
	}
	f.blank()

	groups := groupByNamespace(prog)
	wrote := false
	if root, ok := groups[""]; ok {
		wrote = f.sections(root)
	}
	paths := make([]string, 0, len(groups))
	for path := range groups {
		if path != "" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		if wrote {
			f.blank()
		}
		wrote = true
		g := groups[path]
		if g.empty() {
			f.writef("namespace %s {}\n", quoteString(path))
			continue
		}
		f.writef("namespace %s {\n", quoteString(path))
		f.indent++
		f.sections(g)
		f.indent--
		f.writeln("}")
	}
}

// nsGroup holds the declarations of one namespace path.
type nsGroup struct {
	ResourceTypes []*ResourceDecl
	Permissions   []*PermissionDecl
	Roles         []*RoleDecl
	Policies      []*PolicyDecl
	Relations     []*RelationDecl
}

func (g *nsGroup) empty() bool {
	return len(g.ResourceTypes)+len(g.Permissions)+len(g.Roles)+len(g.Policies)+len(g.Relations) == 0
}

// groupByNamespace splits the program's flat declarations by namespace
// path. A `namespace` block the program declares gets a group even when it
// holds nothing, because an empty block still marks its namespace covered
// for prune.
func groupByNamespace(prog *Program) map[string]*nsGroup {
	groups := make(map[string]*nsGroup)
	get := func(path string) *nsGroup {
		g, ok := groups[path]
		if !ok {
			g = &nsGroup{}
			groups[path] = g
		}
		return g
	}
	for _, rt := range prog.ResourceTypes {
		g := get(rt.NamespacePath)
		g.ResourceTypes = append(g.ResourceTypes, rt)
	}
	for _, p := range prog.Permissions {
		g := get(p.NamespacePath)
		g.Permissions = append(g.Permissions, p)
	}
	for _, r := range prog.Roles {
		g := get(r.NamespacePath)
		g.Roles = append(g.Roles, r)
	}
	for _, p := range prog.Policies {
		g := get(p.NamespacePath)
		g.Policies = append(g.Policies, p)
	}
	for _, r := range prog.Relations {
		g := get(r.NamespacePath)
		g.Relations = append(g.Relations, r)
	}
	var walk func(parent string, nss []*NamespaceDecl)
	walk = func(parent string, nss []*NamespaceDecl) {
		for _, ns := range nss {
			abs := joinNS(parent, ns.Name)
			if abs != "" {
				get(abs)
			}
			walk(abs, ns.Namespaces)
		}
	}
	walk("", prog.Namespaces)
	return groups
}

// sections writes one namespace's declarations in canonical section order,
// with a blank line between sections. It reports whether it wrote anything.
func (f *formatter) sections(g *nsGroup) bool {
	sections := []struct {
		emit  func()
		count int
	}{
		{func() { f.resourceTypes(g.ResourceTypes) }, len(g.ResourceTypes)},
		{func() { f.permissions(g.Permissions) }, len(g.Permissions)},
		{func() { f.roles(g.Roles) }, len(g.Roles)},
		{func() { f.policies(g.Policies) }, len(g.Policies)},
		{func() { f.relations(g.Relations) }, len(g.Relations)},
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
	return !first
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
	f.writef("resource %s {\n", formatName(rt.Name))
	f.indent++
	if rt.Description != "" {
		f.writef("description = %s\n", quoteString(rt.Description))
	}
	// Relations and permissions keep their declared order: it is the order
	// the store keeps, so sorting here would plan a change on every apply.
	for _, rel := range rt.Relations {
		f.relationDef(rel)
	}
	if len(rt.Relations) > 0 && len(rt.Permissions) > 0 {
		f.blank()
	}
	for _, perm := range rt.Permissions {
		f.writef("permission %s = %s\n", formatName(perm.Name), FormatExpr(perm.Expr))
	}
	f.indent--
	f.writeln("}")
}

func (f *formatter) relationDef(rel *RelationDef) {
	subjects := make([]string, 0, len(rel.AllowedSubjects))
	for _, s := range rel.AllowedSubjects {
		if s.Relation == "" {
			subjects = append(subjects, formatName(s.Type))
		} else {
			subjects = append(subjects, formatName(s.Type)+"#"+formatName(s.Relation))
		}
	}
	if len(subjects) == 0 {
		f.writef("relation %s:\n", formatName(rel.Name))
		return
	}
	f.writef("relation %s: %s\n", formatName(rel.Name), strings.Join(subjects, " | "))
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
		f.permission(p)
	}
}

// permission writes the shorthand `permission "n" (resource : action)`
// when there is nothing else to say, and the block form when the
// permission has a description or is a system permission.
func (f *formatter) permission(p *PermissionDecl) {
	if p.Description == "" && !p.IsSystem {
		f.writef("permission %s (%s : %s)\n",
			quoteString(p.Name), formatName(p.Resource), formatName(p.Action))
		return
	}
	f.writef("permission %s {\n", quoteString(p.Name))
	f.indent++
	f.writef("resource = %s\n", formatName(p.Resource))
	f.writef("action = %s\n", formatName(p.Action))
	if p.Description != "" {
		f.writef("description = %s\n", quoteString(p.Description))
	}
	if p.IsSystem {
		f.writeln("is_system = true")
	}
	f.indent--
	f.writeln("}")
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
		f.writef("role %s : %s {\n", formatName(r.Slug), formatParent(r.Parent))
	} else {
		f.writef("role %s {\n", formatName(r.Slug))
	}
	f.indent++
	if r.Name != "" {
		f.writef("name = %s\n", quoteString(r.Name))
	}
	if r.Description != "" {
		f.writef("description = %s\n", quoteString(r.Description))
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
	if r.GrantsSet || len(r.Grants) > 0 || len(r.QualifiedGrants) > 0 {
		op := "="
		if r.GrantsAppend {
			op = "+="
		}
		items := make([]string, 0, len(r.Grants)+len(r.QualifiedGrants))
		for _, g := range r.Grants {
			items = append(items, quoteString(g))
		}
		for _, g := range r.QualifiedGrants {
			items = append(items, fmt.Sprintf("{ namespace = %s, name = %s }", quoteString(g.NamespacePath), quoteString(g.Name)))
		}
		f.writef("grants %s %s\n", op, f.list(items))
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
	f.writef("policy %s {\n", quoteString(p.Name))
	f.indent++
	if p.Description != "" {
		f.writef("description = %s\n", quoteString(p.Description))
	}
	if p.Effect != "" {
		f.writef("effect = %s\n", p.Effect)
	}
	if p.Priority != 0 {
		f.writef("priority = %d\n", p.Priority)
	}
	f.writef("active = %t\n", p.Active)
	if p.NotBefore != nil {
		f.writef("not_before = %s\n", quoteString(p.NotBefore.UTC().Format(time.RFC3339Nano)))
	}
	if p.NotAfter != nil {
		f.writef("not_after = %s\n", quoteString(p.NotAfter.UTC().Format(time.RFC3339Nano)))
	}
	if len(p.Obligations) > 0 {
		f.writef("obligations = %s\n", f.stringList(p.Obligations))
	}
	if len(p.Subjects) > 0 {
		f.writef("subjects = %s\n", f.subjectList(p.Subjects))
	}
	if len(p.Actions) > 0 {
		f.writef("actions = %s\n", f.stringList(p.Actions))
	}
	if len(p.Resources) > 0 {
		f.writef("resources = %s\n", f.stringList(p.Resources))
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
	// A group is non-nil even when empty, so `any_of {}` is written back as
	// itself (and refused by Resolve) instead of as an empty condition.
	if c.AllOf != nil || c.AnyOf != nil {
		kw, inner := "all_of", c.AllOf
		if c.AnyOf != nil {
			kw, inner = "any_of", c.AnyOf
		}
		if len(inner) == 0 {
			f.writef("%s {}\n", kw)
			return
		}
		f.writef("%s {\n", kw)
		f.indent++
		for _, in := range inner {
			f.condition(in)
		}
		f.indent--
		f.writeln("}")
		return
	}
	op := canonicalOp(c.Operator)
	suffix := ""
	if c.Negate {
		suffix = " negate"
	}
	if c.Value == nil {
		// exists / not_exists carry no value. The parser takes a value only
		// on the operator's line, so leaving it out reads back as nil.
		f.writef("%s %s%s\n", formatField(c.Field), op, suffix)
		return
	}
	f.writef("%s %s %s%s\n", formatField(c.Field), op, formatLiteral(c.Value), suffix)
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
		// The whole tuple is the key, so two tuples that differ only in
		// the subject still come out in the same order every time.
		ai := []string{sorted[i].ObjectType, sorted[i].ObjectID, sorted[i].Relation, sorted[i].SubjectType, sorted[i].SubjectID, sorted[i].SubjectRelation}
		bj := []string{sorted[j].ObjectType, sorted[j].ObjectID, sorted[j].Relation, sorted[j].SubjectType, sorted[j].SubjectID, sorted[j].SubjectRelation}
		for k := range ai {
			if ai[k] != bj[k] {
				return ai[k] < bj[k]
			}
		}
		return false
	})
	for _, r := range sorted {
		subj := formatName(r.SubjectType) + ":" + formatName(r.SubjectID)
		if r.SubjectRelation != "" {
			subj += "#" + formatName(r.SubjectRelation)
		}
		f.writef("relation %s:%s %s = %s\n",
			formatName(r.ObjectType), formatName(r.ObjectID), formatName(r.Relation), subj)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

// formatStringList renders []string canonically: inline for ≤ 3 items,
// multi-line with trailing comma otherwise.
func formatStringList(items []string) string {
	return (&formatter{}).stringList(items)
}

func (f *formatter) stringList(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = quoteString(it)
	}
	return f.list(quoted)
}

// list lays out already-rendered items: inline for ≤ 3, otherwise one per
// line, indented one level below the line the list opens on, with a
// trailing comma.
func (f *formatter) list(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	if len(items) <= 3 {
		return "[" + strings.Join(items, ", ") + "]"
	}
	inner := strings.Repeat("    ", f.indent+1)
	var b strings.Builder
	b.WriteString("[\n")
	for _, it := range items {
		b.WriteString(inner)
		b.WriteString(it)
		b.WriteString(",\n")
	}
	b.WriteString(strings.Repeat("    ", f.indent))
	b.WriteString("]")
	return b.String()
}

// subjectList renders a policy's subject matchers. One matcher is written
// inline; more are one per line so each reads as its own row.
func (f *formatter) subjectList(subjects []*SubjectMatchDecl) string {
	items := make([]string, len(subjects))
	for i, m := range subjects {
		var fields []string
		if m.Kind != "" {
			fields = append(fields, "kind = "+quoteString(m.Kind))
		}
		if m.ID != "" {
			fields = append(fields, "id = "+quoteString(m.ID))
		}
		if m.Role != "" {
			fields = append(fields, "role = "+quoteString(m.Role))
		}
		if len(fields) == 0 {
			items[i] = "{}"
		} else {
			items[i] = "{ " + strings.Join(fields, ", ") + " }"
		}
	}
	if len(items) == 1 {
		return "[" + items[0] + "]"
	}
	inner := strings.Repeat("    ", f.indent+1)
	var b strings.Builder
	b.WriteString("[\n")
	for _, it := range items {
		b.WriteString(inner)
		b.WriteString(it)
		b.WriteString(",\n")
	}
	b.WriteString(strings.Repeat("    ", f.indent))
	b.WriteString("]")
	return b.String()
}

// bareName matches what the lexer reads as one identifier.
var bareName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// formatName writes a name bare when the lexer reads it back as the same
// identifier, and as a string literal otherwise (a keyword, a leading
// digit, a space, a colon, a glob, an empty name).
func formatName(s string) string {
	if bareName.MatchString(s) {
		if _, kw := keywords[s]; !kw {
			return s
		}
	}
	return quoteString(s)
}

// formatParent writes a role's parent reference. An absolute path from
// source (`/eng/admin`) is written as it was read; any other parent is a
// slug.
func formatParent(parent string) string {
	if strings.HasPrefix(parent, "/") {
		segs := strings.Split(parent[1:], "/")
		ok := len(segs) > 0
		for _, seg := range segs {
			if formatName(seg) != seg {
				ok = false
				break
			}
		}
		if ok {
			return parent
		}
	}
	return formatName(parent)
}

// formatField writes a condition field bare when it is a dotted path of
// bare words the parser reads back unchanged, and as a string literal
// otherwise (a bracketed key, a space, a segment starting with a digit).
func formatField(field string) string {
	segs := strings.Split(field, ".")
	for i, seg := range segs {
		if !bareName.MatchString(seg) {
			return quoteString(field)
		}
		// A leading all_of / any_of would open a group, not a path.
		if i == 0 && (seg == "all_of" || seg == "any_of") {
			return quoteString(field)
		}
	}
	return field
}

// quoteString writes s as a string literal using only the escapes the lexer
// reads (\\, \", \n, \t, \r), so every string reads back unchanged.
// strconv.Quote would also write \x and \u escapes the lexer keeps as
// literal text.
func quoteString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// formatLiteral renders a condition value. Numbers are written in plain
// decimal (never an exponent, which the lexer does not read). Falls back
// to a quoted fmt.Sprint for types the store never holds for a condition
// the dashboard can write.
func formatLiteral(v any) string {
	switch x := v.(type) {
	case string:
		return quoteString(x)
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	case []string:
		strs := make([]string, len(x))
		for i, e := range x {
			strs[i] = quoteString(e)
		}
		return "[" + strings.Join(strs, ", ") + "]"
	case []any:
		strs := make([]string, len(x))
		for i, e := range x {
			strs[i] = formatLiteral(e)
		}
		return "[" + strings.Join(strs, ", ") + "]"
	}
	return quoteString(fmt.Sprintf("%v", v))
}
