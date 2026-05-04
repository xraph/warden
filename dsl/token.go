// Package dsl implements the .warden declarative configuration language.
//
// The language is purpose-built for warden's domain. Inspired by SpiceDB
// for resource types and permission expressions, with HCL-like blocks for
// roles and policies. One parser, one AST, one set of references — entity
// definitions, permission expressions, and ABAC conditions all share the
// same grammar.
//
// See _project_files/WARDEN-DESIGN.md and the canonical plan for the full
// grammar specification.
package dsl

import "fmt"

// Token represents a single lexed token.
type Token struct {
	Kind  TokenKind
	Value string // raw lexeme; for STRING this is the unescaped string literal
	Pos   Pos
}

// Pos is the source position of a token or AST node.
type Pos struct {
	File string
	Line int // 1-based
	Col  int // 1-based, byte column
}

// String formats the position for error messages.
func (p Pos) String() string {
	if p.File == "" {
		return fmt.Sprintf("%d:%d", p.Line, p.Col)
	}
	return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Col)
}

// TokenKind enumerates lexical token categories.
type TokenKind int

//go:generate stringer -type=TokenKind
const (
	// EOF marks end-of-input.
	EOF TokenKind = iota

	// ILLEGAL is an unrecognized character or unterminated literal.
	ILLEGAL

	// IDENT is a lowercase identifier — `[a-z_][a-z0-9_-]*`.
	IDENT

	// STRING is a double-quoted string literal with the value already
	// unescaped (\\, \", \n, \t).
	STRING

	// INT is an unsigned integer literal — `[0-9]+`.
	INT

	// BOOL is `true` or `false`.
	BOOL

	// Single-character punctuation.
	LBRACE   // {
	RBRACE   // }
	LPAREN   // (
	RPAREN   // )
	LBRACKET // [
	RBRACKET // ]
	COMMA    // ,
	COLON    // :
	SEMI     // ;
	DOT      // .
	PIPE     // |
	HASH     // #
	BANG     // !
	SLASH    // /  (used for absolute namespace paths in role parent refs)

	// Operators.
	ASSIGN  // =
	APPEND  // +=
	ARROW   // ->
	EQ      // ==
	NE      // !=
	LT      // <
	GT      // >
	LE      // <=
	GE      // >=
	PLUS    // +  (also used as union operator on expressions)
	MINUS   // -  (also unary negation)
	AMP     // &  (also intersection on expressions)
	REGEX   // =~

	// Keywords. Lexer picks these out of the IDENT stream.
	WARDEN     // warden
	CONFIG     // config
	TENANT     // tenant
	APP        // app
	NAMESPACE  // namespace
	IMPORT     // import
	RESOURCE   // resource
	RELATION   // relation
	PERMISSION // permission
	ROLE       // role
	POLICY     // policy
	EFFECT     // effect
	ALLOW      // allow
	DENY       // deny
	ACTIONS    // actions
	RESOURCES  // resources
	SUBJECTS   // subjects
	WHEN       // when
	NEGATE     // negate
	GRANTS     // grants
	NAME       // name
	DESCRIPTION // description
	PRIORITY   // priority
	ACTIVE     // active
	IS_SYSTEM  // is_system
	IS_DEFAULT // is_default
	MAX_MEMBERS // max_members
	METADATA    // metadata
	OR          // or
	AND         // and
	NOT         // not
	IN          // in
	CONTAINS    // contains
	STARTS_WITH // starts_with
	ENDS_WITH   // ends_with
	EXISTS      // exists
	IP_IN_CIDR  // ip_in_cidr
	TIME_AFTER  // time_after
	TIME_BEFORE // time_before
	ALL_OF      // all_of
	ANY_OF      // any_of
)

// keywords maps keyword spellings to their TokenKind.
var keywords = map[string]TokenKind{
	"warden":      WARDEN,
	"config":      CONFIG,
	"tenant":      TENANT,
	"app":         APP,
	"namespace":   NAMESPACE,
	"import":      IMPORT,
	"resource":    RESOURCE,
	"relation":    RELATION,
	"permission":  PERMISSION,
	"role":        ROLE,
	"policy":      POLICY,
	"effect":      EFFECT,
	"allow":       ALLOW,
	"deny":        DENY,
	"actions":     ACTIONS,
	"resources":   RESOURCES,
	"subjects":    SUBJECTS,
	"when":        WHEN,
	"negate":      NEGATE,
	"grants":      GRANTS,
	"name":        NAME,
	"description": DESCRIPTION,
	"priority":    PRIORITY,
	"active":      ACTIVE,
	"is_system":   IS_SYSTEM,
	"is_default":  IS_DEFAULT,
	"max_members": MAX_MEMBERS,
	"metadata":    METADATA,
	"or":          OR,
	"and":         AND,
	"not":         NOT,
	"in":          IN,
	"contains":    CONTAINS,
	"starts_with": STARTS_WITH,
	"ends_with":   ENDS_WITH,
	"exists":      EXISTS,
	"ip_in_cidr":  IP_IN_CIDR,
	"time_after":  TIME_AFTER,
	"time_before": TIME_BEFORE,
	"all_of":      ALL_OF,
	"any_of":      ANY_OF,
	"true":        BOOL,
	"false":       BOOL,
}

// String renders a token kind for diagnostics.
func (k TokenKind) String() string {
	switch k {
	case EOF:
		return "EOF"
	case ILLEGAL:
		return "ILLEGAL"
	case IDENT:
		return "IDENT"
	case STRING:
		return "STRING"
	case INT:
		return "INT"
	case BOOL:
		return "BOOL"
	case LBRACE:
		return "{"
	case RBRACE:
		return "}"
	case LPAREN:
		return "("
	case RPAREN:
		return ")"
	case LBRACKET:
		return "["
	case RBRACKET:
		return "]"
	case COMMA:
		return ","
	case COLON:
		return ":"
	case SEMI:
		return ";"
	case DOT:
		return "."
	case PIPE:
		return "|"
	case HASH:
		return "#"
	case BANG:
		return "!"
	case SLASH:
		return "/"
	case ASSIGN:
		return "="
	case APPEND:
		return "+="
	case ARROW:
		return "->"
	case EQ:
		return "=="
	case NE:
		return "!="
	case LT:
		return "<"
	case GT:
		return ">"
	case LE:
		return "<="
	case GE:
		return ">="
	case PLUS:
		return "+"
	case MINUS:
		return "-"
	case AMP:
		return "&"
	case REGEX:
		return "=~"
	}
	for kw, kind := range keywords {
		if kind == k {
			return kw
		}
	}
	return fmt.Sprintf("Token(%d)", int(k))
}
