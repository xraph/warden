package dsl

// Program is the root AST node — one parsed `.warden` file or set of files.
//
// All decls within a program share the same logical namespace; cross-file
// references are resolved against the merged Program.
type Program struct {
	// File this program was parsed from. For multi-file load sets, this is
	// the root path (the load entrypoint).
	File string

	// Header values.
	Version int
	Tenant  string // optional; resolved at apply time
	App     string // optional

	// Top-level declarations.
	ResourceTypes []*ResourceDecl
	Permissions   []*PermissionDecl
	Roles         []*RoleDecl
	Policies      []*PolicyDecl
	Relations     []*RelationDecl
	Imports       []*ImportDecl
	Namespaces    []*NamespaceDecl

	// HeaderPos is the position of the `warden config N` line.
	HeaderPos Pos
}

// ImportDecl is a literal `import "<path>"` directive (reserved for the
// future explicit-import flow; the loader does not consume them today).
type ImportDecl struct {
	Path string
	Pos  Pos
}

// NamespaceDecl wraps a nested `namespace "name" { ... }` block. The parser
// flattens nested namespaces into per-decl NamespacePath strings, but it
// also keeps the original NamespaceDecl tree around for fmt-friendly
// re-emission.
type NamespaceDecl struct {
	// Name is the path segment, not the absolute path.
	Name string

	// Children are the decls declared directly inside this block. After
	// flattening, the absolute namespace path of each is recorded on the
	// decl itself; this field is kept for reference / formatter use.
	ResourceTypes []*ResourceDecl
	Permissions   []*PermissionDecl
	Roles         []*RoleDecl
	Policies      []*PolicyDecl
	Relations     []*RelationDecl
	Namespaces    []*NamespaceDecl

	Pos Pos
}

// ResourceDecl is a `resource <name> { ... }` block.
type ResourceDecl struct {
	Name          string
	NamespacePath string // absolute path, empty = tenant root
	Description   string
	Relations     []*RelationDef
	Permissions   []*ResourcePermissionDecl
	Pos           Pos
}

// RelationDef is a `relation <name>: <subj> | <subj>#<rel> | ...` line
// inside a resource block.
type RelationDef struct {
	Name            string
	AllowedSubjects []SubjectType
	Pos             Pos
}

// SubjectType is one entry in a relation's allowed_subjects list.
// Relation, when non-empty, restricts to a relation-set (`group#member`).
type SubjectType struct {
	Type     string
	Relation string
	Pos      Pos
}

// ResourcePermissionDecl is a `permission <name> = <expr>` inside a resource block.
type ResourcePermissionDecl struct {
	Name string
	Expr Expr
	Pos  Pos
}

// PermissionDecl is a top-level `permission "<name>" (...)` or `{...}` block.
type PermissionDecl struct {
	Name          string // the literal "resource:action" string
	NamespacePath string
	Resource      string // parsed from Name or set explicitly
	Action        string // parsed from Name or set explicitly
	Description   string
	IsSystem      bool
	Pos           Pos
}

// RoleDecl is a `role <slug> [: <parent>] { ... }` block.
type RoleDecl struct {
	Slug          string
	NamespacePath string
	Parent        string // raw — may be a local slug or absolute path starting with "/"
	Name          string
	Description   string
	IsSystem      bool
	IsDefault     bool
	MaxMembers    int
	Grants        []string // permission names; possibly globs
	GrantsAppend  bool     // true if `grants += [...]`
	Pos           Pos
}

// PolicyDecl is a top-level `policy "<name>" { ... }` block.
type PolicyDecl struct {
	Name          string
	NamespacePath string
	Description   string
	Effect        string // "allow" | "deny"
	Priority      int
	Active        bool
	Actions       []string
	Resources     []string
	Conditions    []*Condition
	Pos           Pos
}

// Condition is a single ABAC predicate or boolean group.
//
// Exactly one of {Field+Operator+Value, AllOf, AnyOf} is populated.
type Condition struct {
	// Atomic predicate.
	Field    string
	Operator string
	Value    any
	Negate   bool

	// Boolean groups.
	AllOf []*Condition
	AnyOf []*Condition

	Pos Pos
}

// RelationDecl is a top-level `relation <obj_type>:<obj_id> <rel> = <subj_type>:<subj_id>[#<subj_rel>]`.
type RelationDecl struct {
	NamespacePath   string
	ObjectType      string
	ObjectID        string
	Relation        string
	SubjectType     string
	SubjectID       string
	SubjectRelation string
	Pos             Pos
}

// ─────────────────────────────────────────────────────────────────────────
// Permission expressions (resource-type permissions and traversal).
// ─────────────────────────────────────────────────────────────────────────

// Expr is the interface for permission-expression AST nodes.
type Expr interface {
	exprNode()
	Position() Pos
}

// RefExpr references a relation by name. Used as the leaf of expressions
// inside a resource type ("viewer", "editor").
type RefExpr struct {
	Name string
	Pos  Pos
}

// TraverseExpr is `<rel>->...->target` — walk one or more relation hops and
// then check the final permission/relation on the resulting object.
type TraverseExpr struct {
	// Steps holds at least 2 names: the first is a relation on the current
	// resource type, subsequent names are relations or permissions on the
	// target type after each hop.
	Steps []string
	Pos   Pos
}

// OrExpr is set union (e.g. `viewer or editor`).
type OrExpr struct {
	Left, Right Expr
	Pos         Pos
}

// AndExpr is set intersection (e.g. `editor and not banned`).
type AndExpr struct {
	Left, Right Expr
	Pos         Pos
}

// NotExpr is set complement (e.g. `not banned`).
type NotExpr struct {
	Inner Expr
	Pos   Pos
}

func (e *RefExpr) exprNode()      {}
func (e *RefExpr) Position() Pos  { return e.Pos }
func (e *TraverseExpr) exprNode() {}
func (e *TraverseExpr) Position() Pos {
	return e.Pos
}
func (e *OrExpr) exprNode()      {}
func (e *OrExpr) Position() Pos  { return e.Pos }
func (e *AndExpr) exprNode()     {}
func (e *AndExpr) Position() Pos { return e.Pos }
func (e *NotExpr) exprNode()     {}
func (e *NotExpr) Position() Pos { return e.Pos }
