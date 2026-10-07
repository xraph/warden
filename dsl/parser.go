package dsl

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseRFC3339 parses a timestamp literal as used in PBAC time-bound
// fields (`not_before`, `not_after`). Accepts both RFC3339 and
// RFC3339Nano so authors can write either `"2026-06-01T00:00:00Z"` or
// `"2026-06-01T00:00:00.000Z"` interchangeably.
func parseRFC3339(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 (e.g. \"2026-06-01T00:00:00Z\"), got %q", s)
}

// Parse parses `.warden` source into a Program. Errors are accumulated
// (one per problem) and returned as a slice; a non-nil Program is returned
// even when errors occur, partially populated, so editor tooling can still
// surface useful information.
func Parse(file string, src []byte) (*Program, []*Diagnostic) {
	p := &parser{
		l:    NewLexer(file, src),
		file: file,
	}
	p.advance()
	prog := p.parseProgram()
	prog.File = file
	p.flattenNamespaces(prog)
	return prog, p.errs
}

// Diagnostic is a parser/checker error with a source position and message.
//
//nolint:errname // public API; rename would be a breaking change
type Diagnostic struct {
	Pos Pos
	Msg string
}

func (d *Diagnostic) String() string {
	return fmt.Sprintf("%s: %s", d.Pos, d.Msg)
}

// Error returns the textual diagnostic string for use as an error.
func (d *Diagnostic) Error() string { return d.String() }

type parser struct {
	l    *Lexer
	file string

	cur Token

	errs []*Diagnostic
}

func (p *parser) advance() Token {
	prev := p.cur
	p.cur = p.l.Next()
	return prev
}

func (p *parser) expect(k TokenKind) Token {
	if p.cur.Kind != k {
		p.errf(p.cur.Pos, "expected %s, got %s %q", k, p.cur.Kind, p.cur.Value)
		return p.cur
	}
	return p.advance()
}

func (p *parser) accept(k TokenKind) bool {
	if p.cur.Kind == k {
		p.advance()
		return true
	}
	return false
}

// name reads a name: a bare identifier, or a string literal for a name a
// bare identifier cannot spell (a keyword, a leading digit, a space, a
// colon, a glob). It reports ok=false, and consumes nothing, when the
// current token is neither.
func (p *parser) name() (string, bool) {
	if p.cur.Kind == IDENT || p.cur.Kind == STRING {
		v := p.cur.Value
		p.advance()
		return v, true
	}
	return "", false
}

// isWord reports whether t is a bare word: an identifier or a keyword.
// A field path segment may be either, so `resource.name` and
// `subject.role` read as paths.
func isWord(t Token) bool {
	if t.Kind == IDENT {
		return true
	}
	_, ok := keywords[t.Value]
	return ok && t.Kind != STRING
}

func (p *parser) errf(pos Pos, format string, args ...any) {
	p.errs = append(p.errs, &Diagnostic{Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

// parseProgram is the top-level entry: header followed by zero or more decls.
func (p *parser) parseProgram() *Program {
	prog := &Program{}
	prog.HeaderPos = p.cur.Pos

	// Header is mandatory: `warden config <int>`.
	if p.cur.Kind != WARDEN {
		p.errf(p.cur.Pos, "expected `warden config <version>` header")
	} else {
		p.advance()
		p.expect(CONFIG)
		ver := p.expect(INT)
		if v, err := strconv.Atoi(ver.Value); err == nil {
			prog.Version = v
		}
	}

	// Optional scope keywords.
	for {
		switch p.cur.Kind {
		case TENANT:
			p.advance()
			if v, ok := p.name(); ok {
				prog.Tenant = v
			} else {
				p.errf(p.cur.Pos, "expected tenant identifier after `tenant`")
			}
		case APP:
			p.advance()
			if v, ok := p.name(); ok {
				prog.App = v
			} else {
				p.errf(p.cur.Pos, "expected app identifier after `app`")
			}
		default:
			goto decls
		}
	}
decls:

	for p.cur.Kind != EOF {
		if !p.parseTopLevel(prog, &prog.Namespaces, &prog.ResourceTypes, &prog.Permissions,
			&prog.Roles, &prog.Policies, &prog.Relations) {
			// Skip until we make progress.
			p.advance()
		}
	}
	return prog
}

// parseTopLevel dispatches one top-level declaration into the right slice.
// Returns true if a decl was consumed.
func (p *parser) parseTopLevel(
	prog *Program,
	namespaces *[]*NamespaceDecl,
	resources *[]*ResourceDecl,
	permissions *[]*PermissionDecl,
	roles *[]*RoleDecl,
	policies *[]*PolicyDecl,
	relations *[]*RelationDecl,
) bool {
	switch p.cur.Kind {
	case ILLEGAL:
		p.errf(p.cur.Pos, "lexer error: %s", p.cur.Value)
		p.advance()
		return true
	case IMPORT:
		decl := p.parseImport()
		if decl != nil {
			prog.Imports = append(prog.Imports, decl)
		}
		return true
	case NAMESPACE:
		decl := p.parseNamespace()
		if decl != nil {
			*namespaces = append(*namespaces, decl)
		}
		return true
	case RESOURCE:
		decl := p.parseResource()
		if decl != nil {
			*resources = append(*resources, decl)
		}
		return true
	case PERMISSION:
		decl := p.parsePermission()
		if decl != nil {
			*permissions = append(*permissions, decl)
		}
		return true
	case ROLE:
		decl := p.parseRole()
		if decl != nil {
			*roles = append(*roles, decl)
		}
		return true
	case POLICY:
		decl := p.parsePolicy()
		if decl != nil {
			*policies = append(*policies, decl)
		}
		return true
	case RELATION:
		decl := p.parseTopLevelRelation()
		if decl != nil {
			*relations = append(*relations, decl)
		}
		return true
	case EOF:
		return false
	default:
		p.errf(p.cur.Pos, "unexpected token %s %q at top level", p.cur.Kind, p.cur.Value)
		return false
	}
}

func (p *parser) parseImport() *ImportDecl {
	pos := p.cur.Pos
	p.advance() // consume `import`
	if p.cur.Kind != STRING {
		p.errf(p.cur.Pos, "expected string after `import`")
		return nil
	}
	d := &ImportDecl{Path: p.cur.Value, Pos: pos}
	p.advance()
	return d
}

func (p *parser) parseNamespace() *NamespaceDecl {
	pos := p.cur.Pos
	p.advance() // consume `namespace`
	if p.cur.Kind != STRING && p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected namespace name as identifier or string literal")
		return nil
	}
	name := p.cur.Value
	p.advance()
	if !p.accept(LBRACE) {
		p.errf(p.cur.Pos, "expected `{` to open namespace block")
		return nil
	}
	d := &NamespaceDecl{Name: name, Pos: pos}
	for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
		var dummy []*ImportDecl
		_ = dummy
		switch p.cur.Kind {
		case NAMESPACE:
			if child := p.parseNamespace(); child != nil {
				d.Namespaces = append(d.Namespaces, child)
			}
		case RESOURCE:
			if child := p.parseResource(); child != nil {
				d.ResourceTypes = append(d.ResourceTypes, child)
			}
		case PERMISSION:
			if child := p.parsePermission(); child != nil {
				d.Permissions = append(d.Permissions, child)
			}
		case ROLE:
			if child := p.parseRole(); child != nil {
				d.Roles = append(d.Roles, child)
			}
		case POLICY:
			if child := p.parsePolicy(); child != nil {
				d.Policies = append(d.Policies, child)
			}
		case RELATION:
			if child := p.parseTopLevelRelation(); child != nil {
				d.Relations = append(d.Relations, child)
			}
		default:
			p.errf(p.cur.Pos, "unexpected token %s %q inside namespace", p.cur.Kind, p.cur.Value)
			p.advance()
		}
	}
	p.expect(RBRACE)
	return d
}

func (p *parser) parseResource() *ResourceDecl {
	pos := p.cur.Pos
	p.advance() // consume `resource`
	rtName, ok := p.name()
	if !ok {
		p.errf(p.cur.Pos, "expected resource type name")
		return nil
	}
	d := &ResourceDecl{Name: rtName, Pos: pos}
	if !p.accept(LBRACE) {
		p.errf(p.cur.Pos, "expected `{` to open resource block")
		return nil
	}
	for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
		switch p.cur.Kind {
		case RELATION:
			if rel := p.parseRelationDef(); rel != nil {
				d.Relations = append(d.Relations, rel)
			}
		case PERMISSION:
			if perm := p.parseResourcePermission(); perm != nil {
				d.Permissions = append(d.Permissions, perm)
			}
		case DESCRIPTION:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after description")
			}
			if p.cur.Kind == STRING {
				d.Description = p.cur.Value
				p.advance()
			} else {
				p.errf(p.cur.Pos, "expected string after description =")
			}
		default:
			p.errf(p.cur.Pos, "unexpected token %s %q inside resource block", p.cur.Kind, p.cur.Value)
			p.advance()
		}
	}
	p.expect(RBRACE)
	return d
}

func (p *parser) parseRelationDef() *RelationDef {
	pos := p.cur.Pos
	p.advance() // consume `relation`
	relName, ok := p.name()
	if !ok {
		p.errf(p.cur.Pos, "expected relation name")
		return nil
	}
	def := &RelationDef{Name: relName, Pos: pos}
	if !p.accept(COLON) {
		p.errf(p.cur.Pos, "expected `:` after relation name")
		return nil
	}
	// A relation may list no subject types (`relation x:` with nothing
	// after the colon); the store can hold one. An empty list puts no limit
	// on the subject type: the relation accepts a tuple with any subject.
	if p.cur.Kind != IDENT && p.cur.Kind != STRING {
		return def
	}
	for {
		stPos := p.cur.Pos
		typ, ok := p.name()
		if !ok {
			p.errf(p.cur.Pos, "expected subject type identifier")
			return def
		}
		st := SubjectType{Type: typ, Pos: stPos}
		if p.accept(HASH) {
			if rel, ok := p.name(); ok {
				st.Relation = rel
			} else {
				p.errf(p.cur.Pos, "expected relation name after `#`")
			}
		}
		def.AllowedSubjects = append(def.AllowedSubjects, st)
		if !p.accept(PIPE) {
			break
		}
	}
	return def
}

func (p *parser) parseResourcePermission() *ResourcePermissionDecl {
	pos := p.cur.Pos
	p.advance() // consume `permission`
	permName, ok := p.name()
	if !ok {
		p.errf(p.cur.Pos, "expected permission name (identifier)")
		return nil
	}
	d := &ResourcePermissionDecl{Name: permName, Pos: pos}
	if !p.accept(ASSIGN) {
		p.errf(p.cur.Pos, "expected `=` after permission name")
		return d
	}
	d.Expr = p.parseExpr()
	return d
}

func (p *parser) parsePermission() *PermissionDecl {
	pos := p.cur.Pos
	p.advance() // consume `permission`
	if p.cur.Kind != STRING {
		p.errf(p.cur.Pos, "expected permission name as string literal")
		return nil
	}
	d := &PermissionDecl{Name: p.cur.Value, Pos: pos}
	// The name alone splits at its last ':', because a resource may hold
	// one (warden:role) and an action may not: "warden:role:read" is the
	// resource warden:role and the action read.
	if i := strings.LastIndex(d.Name, ":"); i >= 0 {
		d.Resource = d.Name[:i]
		d.Action = d.Name[i+1:]
	}
	p.advance()

	// Two forms: shorthand `(resource : action)` or block `{ ... }`.
	switch p.cur.Kind {
	case LPAREN:
		p.advance()
		if v, ok := p.name(); ok {
			d.Resource = v
		} else {
			p.errf(p.cur.Pos, "expected resource type identifier")
		}
		if !p.accept(COLON) {
			p.errf(p.cur.Pos, "expected `:` between resource and action")
		}
		if v, ok := p.name(); ok {
			d.Action = v
		} else {
			p.errf(p.cur.Pos, "expected action identifier")
		}
		if !p.accept(RPAREN) {
			p.errf(p.cur.Pos, "expected `)` to close permission shorthand")
		}
	case LBRACE:
		p.advance()
		setResource, setAction := false, false
		for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
			switch p.cur.Kind {
			case RESOURCE:
				p.advance()
				if !p.accept(ASSIGN) {
					p.errf(p.cur.Pos, "expected `=` after `resource`")
				}
				if v, ok := p.name(); ok {
					d.Resource = v
					setResource = true
				} else {
					p.errf(p.cur.Pos, "expected resource identifier")
				}
			case IDENT:
				key := p.cur.Value
				p.advance()
				if !p.accept(ASSIGN) {
					p.errf(p.cur.Pos, "expected `=` after %q", key)
				}
				switch key {
				case "action":
					switch p.cur.Kind {
					case IDENT, STRING:
						d.Action = p.cur.Value
						setAction = true
					default:
						p.errf(p.cur.Pos, "expected action identifier")
					}
					p.advance()
				default:
					p.errf(p.cur.Pos, "unknown permission attribute %q", key)
					p.advance()
				}
			case DESCRIPTION:
				p.advance()
				if !p.accept(ASSIGN) {
					p.errf(p.cur.Pos, "expected `=` after description")
				}
				if p.cur.Kind == STRING {
					d.Description = p.cur.Value
					p.advance()
				}
			case IS_SYSTEM:
				p.advance()
				if !p.accept(ASSIGN) {
					p.errf(p.cur.Pos, "expected `=` after is_system")
				}
				if p.cur.Kind == BOOL {
					d.IsSystem = p.cur.Value == "true"
					p.advance()
				}
			default:
				p.errf(p.cur.Pos, "unexpected token in permission block: %s %q", p.cur.Kind, p.cur.Value)
				p.advance()
			}
		}
		p.expect(RBRACE)
		p.fillFromName(d, pos, setResource, setAction)
	default:
		// No body: the name, split above, gives resource and action.
	}
	return d
}

// fillFromName completes a permission block that sets only one of resource
// and action, taking the other from the name: "a:b:c" with resource "a" has
// the action "b:c", and with action "c" has the resource "a:b". When the
// name does not hold the field that was set, the other one cannot be taken
// from it, and the block is refused rather than given a grant its name does
// not say. The field left unset stays empty, so Resolve refuses the
// declaration too, and an apply that runs despite the parse diagnostic (a
// DeclarativeOnStart load logs them and carries on) writes nothing.
func (p *parser) fillFromName(d *PermissionDecl, pos Pos, setResource, setAction bool) {
	switch {
	case setResource && !setAction:
		if rest, ok := strings.CutPrefix(d.Name, d.Resource+":"); ok {
			d.Action = rest
			return
		}
		d.Action = ""
		p.errf(pos, "permission %q sets resource %q and no action, and its name does not start with %q, so the action cannot be taken from the name; set action too",
			d.Name, d.Resource, d.Resource+":")
	case setAction && !setResource:
		if head, ok := strings.CutSuffix(d.Name, ":"+d.Action); ok {
			d.Resource = head
			return
		}
		d.Resource = ""
		p.errf(pos, "permission %q sets action %q and no resource, and its name does not end with %q, so the resource cannot be taken from the name; set resource too",
			d.Name, d.Action, ":"+d.Action)
	}
}

func (p *parser) parseRole() *RoleDecl {
	pos := p.cur.Pos
	p.advance() // consume `role`
	slug, ok := p.name()
	if !ok {
		p.errf(p.cur.Pos, "expected role slug")
		return nil
	}
	d := &RoleDecl{Slug: slug, Pos: pos}

	// Optional parent: `: <slug>` or `: /seg/seg/.../slug`.
	if p.accept(COLON) {
		switch p.cur.Kind {
		case SLASH:
			// Absolute path: read /seg/seg/.../leaf
			var sb strings.Builder
			sb.WriteString("/")
			p.advance()
			for {
				if p.cur.Kind != IDENT {
					p.errf(p.cur.Pos, "expected identifier in absolute parent path")
					break
				}
				sb.WriteString(p.cur.Value)
				p.advance()
				if !p.accept(SLASH) {
					break
				}
				sb.WriteString("/")
			}
			d.Parent = sb.String()
		case IDENT, STRING:
			d.Parent = p.cur.Value
			p.advance()
		default:
			p.errf(p.cur.Pos, "expected parent role slug after `:`")
		}
	}

	if !p.accept(LBRACE) {
		p.errf(p.cur.Pos, "expected `{` to open role block")
		return d
	}
	for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
		switch p.cur.Kind {
		case NAME:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after name")
			}
			if p.cur.Kind == STRING {
				d.Name = p.cur.Value
				p.advance()
			} else {
				p.errf(p.cur.Pos, "expected string after name =")
			}
		case DESCRIPTION:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after description")
			}
			if p.cur.Kind == STRING {
				d.Description = p.cur.Value
				p.advance()
			}
		case IS_SYSTEM:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after is_system")
			}
			if p.cur.Kind == BOOL {
				d.IsSystem = p.cur.Value == "true"
				p.advance()
			}
		case IS_DEFAULT:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after is_default")
			}
			if p.cur.Kind == BOOL {
				d.IsDefault = p.cur.Value == "true"
				p.advance()
			}
		case MAX_MEMBERS:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after max_members")
			}
			if v, ok := p.parseSignedInt("max_members"); ok {
				d.MaxMembers = v
			}
		case GRANTS:
			p.advance()
			if p.cur.Kind == APPEND {
				d.GrantsAppend = true
				p.advance()
			} else if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` or `+=` after grants")
			}
			d.GrantsSet = true
			p.parseGrantList(d)
		default:
			p.errf(p.cur.Pos, "unexpected token in role block: %s %q", p.cur.Kind, p.cur.Value)
			p.advance()
		}
	}
	p.expect(RBRACE)
	return d
}

func (p *parser) parsePolicy() *PolicyDecl {
	pos := p.cur.Pos
	p.advance() // consume `policy`
	if p.cur.Kind != STRING {
		p.errf(p.cur.Pos, "expected policy name as string literal")
		return nil
	}
	d := &PolicyDecl{Name: p.cur.Value, Pos: pos, Active: true}
	p.advance()
	if !p.accept(LBRACE) {
		p.errf(p.cur.Pos, "expected `{` to open policy block")
		return d
	}
	for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
		switch p.cur.Kind {
		case EFFECT:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after effect")
			}
			switch p.cur.Kind {
			case ALLOW:
				d.Effect = "allow"
				p.advance()
			case DENY:
				d.Effect = "deny"
				p.advance()
			default:
				p.errf(p.cur.Pos, "expected `allow` or `deny`, got %s %q", p.cur.Kind, p.cur.Value)
				p.advance()
			}
		case PRIORITY:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after priority")
			}
			if v, ok := p.parseSignedInt("priority"); ok {
				d.Priority = v
			}
		case ACTIVE:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after active")
			}
			if p.cur.Kind == BOOL {
				d.Active = p.cur.Value == "true"
				p.advance()
			}
		case SUBJECTS:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after subjects")
			}
			d.Subjects = append(d.Subjects, p.parseSubjectList()...)
		case ACTIONS:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after actions")
			}
			d.Actions = append(d.Actions, p.parseStringList()...)
		case RESOURCES:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after resources")
			}
			d.Resources = append(d.Resources, p.parseStringList()...)
		case DESCRIPTION:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after description")
			}
			if p.cur.Kind == STRING {
				d.Description = p.cur.Value
				p.advance()
			}
		case NOT_BEFORE:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after not_before")
			}
			if p.cur.Kind == STRING {
				if t, err := parseRFC3339(p.cur.Value); err != nil {
					p.errf(p.cur.Pos, "not_before must be RFC3339 timestamp: %v", err)
				} else {
					d.NotBefore = &t
				}
				p.advance()
			} else {
				p.errf(p.cur.Pos, "expected RFC3339 timestamp string after not_before =")
			}
		case NOT_AFTER:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after not_after")
			}
			if p.cur.Kind == STRING {
				if t, err := parseRFC3339(p.cur.Value); err != nil {
					p.errf(p.cur.Pos, "not_after must be RFC3339 timestamp: %v", err)
				} else {
					d.NotAfter = &t
				}
				p.advance()
			} else {
				p.errf(p.cur.Pos, "expected RFC3339 timestamp string after not_after =")
			}
		case OBLIGATIONS:
			p.advance()
			if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` after obligations")
			}
			d.Obligations = append(d.Obligations, p.parseStringList()...)
		case WHEN:
			p.advance()
			if !p.accept(LBRACE) {
				p.errf(p.cur.Pos, "expected `{` after `when`")
				continue
			}
			for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
				if c := p.parseCondition(); c != nil {
					d.Conditions = append(d.Conditions, c)
				}
			}
			p.expect(RBRACE)
		default:
			p.errf(p.cur.Pos, "unexpected token in policy block: %s %q", p.cur.Kind, p.cur.Value)
			p.advance()
		}
	}
	p.expect(RBRACE)
	return d
}

// parseCondition parses one ABAC predicate: either an atomic
// `<field> <op> <value> [negate]` form or a `all_of { ... }` / `any_of { ... }` group.
func (p *parser) parseCondition() *Condition {
	pos := p.cur.Pos
	switch p.cur.Kind {
	case ALL_OF:
		p.advance()
		if !p.accept(LBRACE) {
			p.errf(p.cur.Pos, "expected `{` after all_of")
			return nil
		}
		c := &Condition{Pos: pos, AllOf: []*Condition{}}
		for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
			if inner := p.parseCondition(); inner != nil {
				c.AllOf = append(c.AllOf, inner)
			}
		}
		p.expect(RBRACE)
		return c
	case ANY_OF:
		p.advance()
		if !p.accept(LBRACE) {
			p.errf(p.cur.Pos, "expected `{` after any_of")
			return nil
		}
		c := &Condition{Pos: pos, AnyOf: []*Condition{}}
		for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
			if inner := p.parseCondition(); inner != nil {
				c.AnyOf = append(c.AnyOf, inner)
			}
		}
		p.expect(RBRACE)
		return c
	}

	// Atomic predicate: field-path operator value [negate]. A field a bare
	// path cannot spell is written as a string literal.
	var field string
	if p.cur.Kind == STRING {
		field = p.cur.Value
		p.advance()
	} else {
		field = p.parseFieldPath()
	}
	if field == "" {
		p.advance() // ensure progress
		return nil
	}

	opLine := p.cur.Pos.Line
	op, ok := p.parseOperator()
	if !ok {
		return nil
	}

	// exists and not_exists test presence, so their value is optional. One
	// is read only when it starts on the operator's own line, so the next
	// condition (which may start with a quoted field) is never taken for it.
	var value any
	if (op != "exists" && op != "not_exists") || (p.cur.Pos.Line == opLine && startsLiteral(p.cur.Kind)) {
		value, ok = p.parseLiteralValue()
		if !ok {
			return nil
		}
	}

	c := &Condition{Field: field, Operator: op, Value: value, Pos: pos}
	if p.accept(NEGATE) {
		c.Negate = true
	}
	return c
}

// parseFieldPath reads a dotted field path. Each segment is a bare word,
// and a keyword counts as one (`resource.name`, `subject.role`).
func (p *parser) parseFieldPath() string {
	if !isWord(p.cur) {
		p.errf(p.cur.Pos, "expected field path identifier, got %s %q", p.cur.Kind, p.cur.Value)
		return ""
	}
	var sb strings.Builder
	sb.WriteString(p.cur.Value)
	p.advance()
	for p.accept(DOT) {
		switch {
		case isWord(p.cur):
			sb.WriteString(".")
			sb.WriteString(p.cur.Value)
			p.advance()
		case p.cur.Kind == LBRACKET:
			// .[...] for map access
			p.advance()
			if p.cur.Kind == STRING {
				sb.WriteString("[")
				sb.WriteString(strconv.Quote(p.cur.Value))
				sb.WriteString("]")
				p.advance()
			}
			p.expect(RBRACKET)
		default:
			p.errf(p.cur.Pos, "expected identifier after `.`")
			return sb.String()
		}
	}
	return sb.String()
}

// startsLiteral reports whether a token of kind k can open a literal value.
func startsLiteral(k TokenKind) bool {
	switch k {
	case STRING, INT, FLOAT, BOOL, LBRACKET, MINUS:
		return true
	}
	return false
}

// parseOperator reads one of the keyword/operator-spelled comparison ops.
// Returns the canonical policy.Operator string.
func (p *parser) parseOperator() (string, bool) {
	pos := p.cur.Pos
	switch p.cur.Kind {
	case EQ:
		p.advance()
		return "eq", true
	case NE:
		p.advance()
		return "neq", true
	case IN:
		p.advance()
		return "in", true
	case NOT:
		// `not in`, `not exists`
		p.advance()
		switch p.cur.Kind {
		case IN:
			p.advance()
			return "not_in", true
		case EXISTS:
			p.advance()
			return "not_exists", true
		}
		p.errf(p.cur.Pos, "expected `in` or `exists` after `not`")
		return "", false
	case CONTAINS:
		p.advance()
		return "contains", true
	case STARTS_WITH:
		p.advance()
		return "starts_with", true
	case ENDS_WITH:
		p.advance()
		return "ends_with", true
	case GT:
		p.advance()
		return "gt", true
	case LT:
		p.advance()
		return "lt", true
	case GE:
		p.advance()
		return "gte", true
	case LE:
		p.advance()
		return "lte", true
	case EXISTS:
		p.advance()
		return "exists", true
	case IP_IN_CIDR:
		p.advance()
		return "ip_in_cidr", true
	case TIME_AFTER:
		p.advance()
		return "time_after", true
	case TIME_BEFORE:
		p.advance()
		return "time_before", true
	case REGEX:
		p.advance()
		return "regex", true
	}
	p.errf(pos, "expected condition operator, got %s %q", p.cur.Kind, p.cur.Value)
	return "", false
}

// parseLiteralValue reads the right-hand side of a condition: a string, a
// number (an int, or a float64 for a decimal, either with an optional
// leading `-`), a bool, or a list of these. A list of strings only is a
// []string; any other list is a []any.
func (p *parser) parseLiteralValue() (any, bool) {
	switch p.cur.Kind {
	case STRING:
		v := p.cur.Value
		p.advance()
		return v, true
	case INT, FLOAT, MINUS:
		return p.parseNumber()
	case BOOL:
		v := p.cur.Value == "true"
		p.advance()
		return v, true
	case LBRACKET:
		return p.parseValueList()
	}
	p.errf(p.cur.Pos, "expected literal value, got %s %q", p.cur.Kind, p.cur.Value)
	return nil, false
}

// parseSignedInt reads an INT with an optional leading `-`, for an integer
// field the store keeps signed (priority, max_members).
func (p *parser) parseSignedInt(what string) (int, bool) {
	neg := p.accept(MINUS)
	if p.cur.Kind != INT {
		p.errf(p.cur.Pos, "expected an integer after %s =, got %s %q", what, p.cur.Kind, p.cur.Value)
		return 0, false
	}
	tok := p.advance()
	raw := tok.Value
	if neg {
		raw = "-" + raw
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		p.errf(tok.Pos, "invalid integer %q for %s: %v", raw, what, err)
		return 0, false
	}
	return v, true
}

// parseNumber reads an INT or FLOAT with an optional leading `-`.
func (p *parser) parseNumber() (any, bool) {
	neg := p.accept(MINUS)
	tok := p.cur
	switch tok.Kind {
	case INT:
		p.advance()
		raw := tok.Value
		if neg {
			raw = "-" + raw
		}
		i, err := strconv.Atoi(raw)
		if err != nil {
			// Too large for an int: read it as the float64 it came from
			// (Format writes a large whole float64 without a decimal point).
			f, ferr := strconv.ParseFloat(raw, 64)
			if ferr != nil {
				p.errf(tok.Pos, "invalid integer literal %q: %v", raw, err)
				return nil, false
			}
			return f, true
		}
		return i, true
	case FLOAT:
		p.advance()
		f, err := strconv.ParseFloat(tok.Value, 64)
		if err != nil {
			p.errf(tok.Pos, "invalid number literal %q: %v", tok.Value, err)
			return nil, false
		}
		if neg {
			f = -f
		}
		return f, true
	}
	p.errf(tok.Pos, "expected a number after `-`, got %s %q", tok.Kind, tok.Value)
	return nil, false
}

// parseValueList reads `[` literal, ... `]` for a condition value.
func (p *parser) parseValueList() (any, bool) {
	if !p.accept(LBRACKET) {
		p.errf(p.cur.Pos, "expected `[` to open list")
		return nil, false
	}
	var items []any
	var strs []string
	allStrings := true
	for p.cur.Kind != RBRACKET && p.cur.Kind != EOF {
		if p.cur.Kind == LBRACKET {
			p.errf(p.cur.Pos, "a list value cannot hold another list")
			p.advance()
			continue
		}
		v, ok := p.parseLiteralValue()
		if !ok {
			p.advance()
			continue
		}
		if str, isStr := v.(string); isStr {
			strs = append(strs, str)
		} else {
			allStrings = false
		}
		items = append(items, v)
		if !p.accept(COMMA) {
			break
		}
	}
	p.expect(RBRACKET)
	if allStrings {
		return strs, true
	}
	return items, true
}

// parseSubjectList reads a policy's `subjects` value: a list of matchers,
// each `{ kind = "...", id = "...", role = "..." }` with every field
// optional. `{}` is the empty matcher.
func (p *parser) parseSubjectList() []*SubjectMatchDecl {
	if !p.accept(LBRACKET) {
		p.errf(p.cur.Pos, "expected `[` to open the subjects list")
		return nil
	}
	var out []*SubjectMatchDecl
	for p.cur.Kind != RBRACKET && p.cur.Kind != EOF {
		if p.cur.Kind != LBRACE {
			p.errf(p.cur.Pos, "expected a subject matcher `{ kind = ..., id = ..., role = ... }`, got %s %q", p.cur.Kind, p.cur.Value)
			p.advance()
			continue
		}
		m := &SubjectMatchDecl{Pos: p.cur.Pos}
		fields := p.parseObject("subject matcher", "kind", "id", "role")
		m.Kind, m.ID, m.Role = fields["kind"], fields["id"], fields["role"]
		out = append(out, m)
		if !p.accept(COMMA) {
			break
		}
	}
	p.expect(RBRACKET)
	return out
}

// parseGrantList reads a role's `grants` value: a list of permission names
// and qualified grants `{ namespace = "...", name = "..." }`.
func (p *parser) parseGrantList(d *RoleDecl) {
	if !p.accept(LBRACKET) {
		p.errf(p.cur.Pos, "expected `[` to open string list")
		return
	}
	for p.cur.Kind != RBRACKET && p.cur.Kind != EOF {
		switch p.cur.Kind {
		case STRING:
			d.Grants = append(d.Grants, p.cur.Value)
			p.advance()
		case LBRACE:
			pos := p.cur.Pos
			fields := p.parseObject("qualified grant", "namespace", "name")
			if _, ok := fields["name"]; !ok {
				p.errf(pos, "a qualified grant needs a name")
			}
			d.QualifiedGrants = append(d.QualifiedGrants, &GrantRef{
				NamespacePath: fields["namespace"], Name: fields["name"], Pos: pos,
			})
		default:
			p.errf(p.cur.Pos, "expected string literal or a qualified grant `{ namespace = ..., name = ... }`")
			p.advance()
			continue
		}
		if !p.accept(COMMA) {
			break
		}
	}
	p.expect(RBRACKET)
}

// parseObject reads `{ key = "value", ... }` where every value is a string
// literal and every key is one of keys (bare, and a keyword may be one).
// The commas between fields are optional. It returns the fields present.
func (p *parser) parseObject(what string, keys ...string) map[string]string {
	fields := make(map[string]string)
	p.expect(LBRACE)
	for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
		keyTok := p.cur
		if !isWord(keyTok) {
			p.errf(keyTok.Pos, "expected a %s field (%s), got %s %q", what, strings.Join(keys, ", "), keyTok.Kind, keyTok.Value)
			p.advance()
			continue
		}
		p.advance()
		known := false
		for _, k := range keys {
			if k == keyTok.Value {
				known = true
				break
			}
		}
		if !known {
			p.errf(keyTok.Pos, "unknown %s field %q: expected %s", what, keyTok.Value, strings.Join(keys, ", "))
		}
		if !p.accept(ASSIGN) {
			p.errf(p.cur.Pos, "expected `=` after %q", keyTok.Value)
		}
		if p.cur.Kind != STRING {
			p.errf(p.cur.Pos, "expected a string after %s =", keyTok.Value)
		} else {
			if _, dup := fields[keyTok.Value]; dup {
				p.errf(keyTok.Pos, "%s field %q is given twice", what, keyTok.Value)
			}
			if known {
				fields[keyTok.Value] = p.cur.Value
			}
			p.advance()
		}
		p.accept(COMMA)
	}
	p.expect(RBRACE)
	return fields
}

func (p *parser) parseStringList() []string {
	if !p.accept(LBRACKET) {
		p.errf(p.cur.Pos, "expected `[` to open string list")
		return nil
	}
	var out []string
	for p.cur.Kind != RBRACKET && p.cur.Kind != EOF {
		if p.cur.Kind != STRING {
			p.errf(p.cur.Pos, "expected string literal")
			p.advance()
			continue
		}
		out = append(out, p.cur.Value)
		p.advance()
		if !p.accept(COMMA) {
			break
		}
	}
	p.expect(RBRACKET)
	return out
}

func (p *parser) parseTopLevelRelation() *RelationDecl {
	pos := p.cur.Pos
	p.advance() // consume `relation`
	d := &RelationDecl{Pos: pos}
	var ok bool
	if d.ObjectType, ok = p.name(); !ok {
		p.errf(p.cur.Pos, "expected object type")
		return nil
	}
	if !p.accept(COLON) {
		p.errf(p.cur.Pos, "expected `:` after object type")
		return d
	}
	if d.ObjectID, ok = p.name(); !ok {
		p.errf(p.cur.Pos, "expected object id")
		return d
	}
	if d.Relation, ok = p.name(); !ok {
		p.errf(p.cur.Pos, "expected relation name")
		return d
	}
	if !p.accept(ASSIGN) {
		p.errf(p.cur.Pos, "expected `=` after relation name")
		return d
	}
	if d.SubjectType, ok = p.name(); !ok {
		p.errf(p.cur.Pos, "expected subject type")
		return d
	}
	if !p.accept(COLON) {
		p.errf(p.cur.Pos, "expected `:` after subject type")
		return d
	}
	if d.SubjectID, ok = p.name(); !ok {
		p.errf(p.cur.Pos, "expected subject id")
		return d
	}
	if p.accept(HASH) {
		if d.SubjectRelation, ok = p.name(); !ok {
			p.errf(p.cur.Pos, "expected relation name after `#`")
		}
	}
	return d
}

// ─────────────────────────────────────────────────────────────────────────
// Permission expressions (Pratt-style precedence: or < and < not < traversal).
// ─────────────────────────────────────────────────────────────────────────

func (p *parser) parseExpr() Expr {
	return p.parseOrExpr()
}

func (p *parser) parseOrExpr() Expr {
	left := p.parseAndExpr()
	for {
		switch p.cur.Kind {
		case OR, PLUS:
			pos := p.cur.Pos
			p.advance()
			right := p.parseAndExpr()
			left = &OrExpr{Left: left, Right: right, Pos: pos}
		default:
			return left
		}
	}
}

func (p *parser) parseAndExpr() Expr {
	left := p.parseNotExpr()
	for {
		switch p.cur.Kind {
		case AND, AMP:
			pos := p.cur.Pos
			p.advance()
			right := p.parseNotExpr()
			left = &AndExpr{Left: left, Right: right, Pos: pos}
		default:
			return left
		}
	}
}

func (p *parser) parseNotExpr() Expr {
	switch p.cur.Kind {
	case NOT, BANG, MINUS:
		pos := p.cur.Pos
		p.advance()
		inner := p.parseNotExpr()
		return &NotExpr{Inner: inner, Pos: pos}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() Expr {
	switch p.cur.Kind {
	case LPAREN:
		p.advance()
		e := p.parseExpr()
		if !p.accept(RPAREN) {
			p.errf(p.cur.Pos, "expected `)`")
		}
		return e
	case IDENT:
		pos := p.cur.Pos
		first := p.cur.Value
		p.advance()
		if p.cur.Kind != ARROW {
			return &RefExpr{Name: first, Pos: pos}
		}
		// Traversal chain.
		steps := []string{first}
		for p.accept(ARROW) {
			if p.cur.Kind != IDENT {
				p.errf(p.cur.Pos, "expected identifier after `->`")
				break
			}
			steps = append(steps, p.cur.Value)
			p.advance()
		}
		return &TraverseExpr{Steps: steps, Pos: pos}
	}
	p.errf(p.cur.Pos, "expected expression, got %s %q", p.cur.Kind, p.cur.Value)
	// Fabricate a placeholder so tree shape is sane.
	return &RefExpr{Name: "<error>", Pos: p.cur.Pos}
}

// ─────────────────────────────────────────────────────────────────────────
// Namespace flattening.
// ─────────────────────────────────────────────────────────────────────────

// flattenNamespaces walks NamespaceDecl trees and stamps the absolute
// namespace path on every wrapped decl, then promotes them to the program's
// flat decl slices. This means downstream stages (resolver, applier) only
// need to look at the flat slices.
func (p *parser) flattenNamespaces(prog *Program) {
	for _, ns := range prog.Namespaces {
		p.flattenInto(ns, "", prog)
	}
}

func (p *parser) flattenInto(ns *NamespaceDecl, parent string, prog *Program) {
	abs := joinNS(parent, ns.Name)
	for _, r := range ns.ResourceTypes {
		r.NamespacePath = abs
		prog.ResourceTypes = append(prog.ResourceTypes, r)
	}
	for _, perm := range ns.Permissions {
		perm.NamespacePath = abs
		prog.Permissions = append(prog.Permissions, perm)
	}
	for _, role := range ns.Roles {
		role.NamespacePath = abs
		prog.Roles = append(prog.Roles, role)
	}
	for _, pol := range ns.Policies {
		pol.NamespacePath = abs
		prog.Policies = append(prog.Policies, pol)
	}
	for _, rel := range ns.Relations {
		rel.NamespacePath = abs
		prog.Relations = append(prog.Relations, rel)
	}
	for _, child := range ns.Namespaces {
		p.flattenInto(child, abs, prog)
	}
}

func joinNS(parent, child string) string {
	switch {
	case parent == "":
		return child
	case child == "":
		return parent
	default:
		return parent + "/" + child
	}
}
