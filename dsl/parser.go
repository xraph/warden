package dsl

import (
	"fmt"
	"strconv"
	"strings"
)

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

	cur, next Token
	hasNext   bool

	errs []*Diagnostic
}

func (p *parser) advance() Token {
	prev := p.cur
	if p.hasNext {
		p.cur = p.next
		p.hasNext = false
	} else {
		p.cur = p.l.Next()
	}
	return prev
}

func (p *parser) peek() Token {
	if !p.hasNext {
		p.next = p.l.Next()
		p.hasNext = true
	}
	return p.next
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
			if p.cur.Kind == IDENT {
				prog.Tenant = p.cur.Value
				p.advance()
			} else {
				p.errf(p.cur.Pos, "expected tenant identifier after `tenant`")
			}
		case APP:
			p.advance()
			if p.cur.Kind == IDENT {
				prog.App = p.cur.Value
				p.advance()
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
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected resource type name")
		return nil
	}
	d := &ResourceDecl{Name: p.cur.Value, Pos: pos}
	p.advance()
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
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected relation name")
		return nil
	}
	def := &RelationDef{Name: p.cur.Value, Pos: pos}
	p.advance()
	if !p.accept(COLON) {
		p.errf(p.cur.Pos, "expected `:` after relation name")
		return nil
	}
	for {
		if p.cur.Kind != IDENT {
			p.errf(p.cur.Pos, "expected subject type identifier")
			return def
		}
		st := SubjectType{Type: p.cur.Value, Pos: p.cur.Pos}
		p.advance()
		if p.accept(HASH) {
			if p.cur.Kind != IDENT {
				p.errf(p.cur.Pos, "expected relation name after `#`")
			} else {
				st.Relation = p.cur.Value
				p.advance()
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
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected permission name (identifier)")
		return nil
	}
	d := &ResourcePermissionDecl{Name: p.cur.Value, Pos: pos}
	p.advance()
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
	if i := strings.Index(d.Name, ":"); i >= 0 {
		d.Resource = d.Name[:i]
		d.Action = d.Name[i+1:]
	}
	p.advance()

	// Two forms: shorthand `(resource : action)` or block `{ ... }`.
	switch p.cur.Kind {
	case LPAREN:
		p.advance()
		if p.cur.Kind != IDENT {
			p.errf(p.cur.Pos, "expected resource type identifier")
		} else {
			d.Resource = p.cur.Value
			p.advance()
		}
		if !p.accept(COLON) {
			p.errf(p.cur.Pos, "expected `:` between resource and action")
		}
		if p.cur.Kind != IDENT {
			p.errf(p.cur.Pos, "expected action identifier")
		} else {
			d.Action = p.cur.Value
			p.advance()
		}
		if !p.accept(RPAREN) {
			p.errf(p.cur.Pos, "expected `)` to close permission shorthand")
		}
	case LBRACE:
		p.advance()
		for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
			switch p.cur.Kind {
			case RESOURCE:
				p.advance()
				if !p.accept(ASSIGN) {
					p.errf(p.cur.Pos, "expected `=` after `resource`")
				}
				if p.cur.Kind == IDENT {
					d.Resource = p.cur.Value
					p.advance()
				}
			case IDENT:
				key := p.cur.Value
				p.advance()
				if !p.accept(ASSIGN) {
					p.errf(p.cur.Pos, "expected `=` after %q", key)
				}
				switch key {
				case "action":
					if p.cur.Kind == IDENT {
						d.Action = p.cur.Value
					} else if p.cur.Kind == STRING {
						d.Action = p.cur.Value
					} else {
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
	default:
		// Naked permission, no body — name is enough if it's already resource:action.
	}
	return d
}

func (p *parser) parseRole() *RoleDecl {
	pos := p.cur.Pos
	p.advance() // consume `role`
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected role slug")
		return nil
	}
	d := &RoleDecl{Slug: p.cur.Value, Pos: pos}
	p.advance()

	// Optional parent: `: <slug>` or `: /seg/seg/.../slug`.
	if p.accept(COLON) {
		if p.cur.Kind == SLASH {
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
		} else if p.cur.Kind == IDENT {
			d.Parent = p.cur.Value
			p.advance()
		} else {
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
			if p.cur.Kind == INT {
				if v, err := strconv.Atoi(p.cur.Value); err == nil {
					d.MaxMembers = v
				}
				p.advance()
			}
		case GRANTS:
			p.advance()
			if p.cur.Kind == APPEND {
				d.GrantsAppend = true
				p.advance()
			} else if !p.accept(ASSIGN) {
				p.errf(p.cur.Pos, "expected `=` or `+=` after grants")
			}
			d.Grants = append(d.Grants, p.parseStringList()...)
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
			if p.cur.Kind == INT {
				if v, err := strconv.Atoi(p.cur.Value); err == nil {
					d.Priority = v
				}
				p.advance()
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
		c := &Condition{Pos: pos}
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
		c := &Condition{Pos: pos}
		for p.cur.Kind != RBRACE && p.cur.Kind != EOF {
			if inner := p.parseCondition(); inner != nil {
				c.AnyOf = append(c.AnyOf, inner)
			}
		}
		p.expect(RBRACE)
		return c
	}

	// Atomic predicate: field-path operator value [negate].
	field := p.parseFieldPath()
	if field == "" {
		p.advance() // ensure progress
		return nil
	}

	op, ok := p.parseOperator()
	if !ok {
		return nil
	}

	value, ok := p.parseLiteralValue()
	if !ok {
		return nil
	}

	c := &Condition{Field: field, Operator: op, Value: value, Pos: pos}
	if p.accept(NEGATE) {
		c.Negate = true
	}
	return c
}

func (p *parser) parseFieldPath() string {
	if p.cur.Kind != IDENT && p.cur.Kind != SUBJECTS && p.cur.Kind != ACTIONS && p.cur.Kind != RESOURCES {
		p.errf(p.cur.Pos, "expected field path identifier, got %s %q", p.cur.Kind, p.cur.Value)
		return ""
	}
	var sb strings.Builder
	sb.WriteString(p.cur.Value)
	p.advance()
	for p.accept(DOT) {
		if p.cur.Kind == IDENT {
			sb.WriteString(".")
			sb.WriteString(p.cur.Value)
			p.advance()
		} else if p.cur.Kind == LBRACKET {
			// .[...] for map access
			p.advance()
			if p.cur.Kind == STRING {
				sb.WriteString("[")
				sb.WriteString(strconv.Quote(p.cur.Value))
				sb.WriteString("]")
				p.advance()
			}
			p.expect(RBRACKET)
		} else {
			p.errf(p.cur.Pos, "expected identifier after `.`")
			break
		}
	}
	return sb.String()
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

// parseLiteralValue reads a string, int, bool, or string list as the right-hand
// side of a condition.
func (p *parser) parseLiteralValue() (any, bool) {
	switch p.cur.Kind {
	case STRING:
		v := p.cur.Value
		p.advance()
		return v, true
	case INT:
		i, _ := strconv.Atoi(p.cur.Value)
		p.advance()
		return i, true
	case BOOL:
		v := p.cur.Value == "true"
		p.advance()
		return v, true
	case LBRACKET:
		return p.parseStringList(), true
	}
	p.errf(p.cur.Pos, "expected literal value, got %s %q", p.cur.Kind, p.cur.Value)
	return nil, false
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
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected object type")
		return nil
	}
	d.ObjectType = p.cur.Value
	p.advance()
	if !p.accept(COLON) {
		p.errf(p.cur.Pos, "expected `:` after object type")
		return d
	}
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected object id")
		return d
	}
	d.ObjectID = p.cur.Value
	p.advance()
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected relation name")
		return d
	}
	d.Relation = p.cur.Value
	p.advance()
	if !p.accept(ASSIGN) {
		p.errf(p.cur.Pos, "expected `=` after relation name")
		return d
	}
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected subject type")
		return d
	}
	d.SubjectType = p.cur.Value
	p.advance()
	if !p.accept(COLON) {
		p.errf(p.cur.Pos, "expected `:` after subject type")
		return d
	}
	if p.cur.Kind != IDENT {
		p.errf(p.cur.Pos, "expected subject id")
		return d
	}
	d.SubjectID = p.cur.Value
	p.advance()
	if p.accept(HASH) {
		if p.cur.Kind == IDENT {
			d.SubjectRelation = p.cur.Value
			p.advance()
		} else {
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
