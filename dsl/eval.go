package dsl

import (
	"context"
	"strings"
	"sync"

	"github.com/xraph/warden/relation"
)

// CompileExpr parses a textual permission expression into an AST.
// Used by the engine to compile ResourceType.Permissions[].Expression
// at Check time (with caching).
func CompileExpr(file string, src string) (Expr, []*Diagnostic) {
	p := &parser{
		l:    NewLexer(file, []byte(src)),
		file: file,
	}
	p.advance()
	expr := p.parseExpr()
	if p.cur.Kind != EOF {
		p.errf(p.cur.Pos, "unexpected trailing tokens after expression")
	}
	return expr, p.errs
}

// EvalContext is the runtime input to expression evaluation.
//
// The evaluator walks an Expr AST against the relation graph to decide
// whether `subject` has the named permission on `resource`. It uses the
// store to look up tuples and recurses across traversal hops up to a
// bounded depth (taken from MaxDepth).
type EvalContext struct {
	TenantID      string
	NamespacePath string

	ObjectType string
	ObjectID   string

	SubjectType string
	SubjectID   string

	// MaxDepth bounds traversal recursion. The engine sets this from its
	// configured graph walker depth.
	MaxDepth int
}

// PermResolver returns the compiled permission expression for a resource
// type's named permission, if one exists. Used by the traversal walker to
// recursively evaluate permissions across resource-type hops
// (e.g. `parent->read` where `read` is itself a permission expression on
// the hopped resource type).
//
// Returns (nil, false) when no expression is defined for that combination.
type PermResolver func(ctx context.Context, tenantID, namespacePath, resourceType, permName string) (Expr, bool)

// Evaluator evaluates resource-type permission expressions.
type Evaluator struct {
	relStore relation.Store
	resolve  PermResolver // optional; enables traversal into permissions

	mu    sync.RWMutex
	cache map[string]Expr // keyed by `tenant\x00ns\x00restype\x00perm`
}

// NewEvaluator constructs an evaluator backed by the given relation store.
func NewEvaluator(relStore relation.Store) *Evaluator {
	return &Evaluator{
		relStore: relStore,
		cache:    make(map[string]Expr),
	}
}

// WithPermResolver sets the permission resolver used during traversal to
// recursively evaluate permissions on hopped-to resource types.
func (e *Evaluator) WithPermResolver(r PermResolver) *Evaluator {
	e.resolve = r
	return e
}

// CompileAndCache parses the expression for a resource-type permission and
// caches the result. Subsequent Eval calls reuse the AST.
func (e *Evaluator) CompileAndCache(tenantID, ns, resourceType, permName, exprSrc string) (Expr, []*Diagnostic) {
	key := cacheKey(tenantID, ns, resourceType, permName)
	e.mu.RLock()
	if expr, ok := e.cache[key]; ok {
		e.mu.RUnlock()
		return expr, nil
	}
	e.mu.RUnlock()
	expr, diags := CompileExpr("<inline>", exprSrc)
	if len(diags) > 0 {
		return expr, diags
	}
	e.mu.Lock()
	e.cache[key] = expr
	e.mu.Unlock()
	return expr, nil
}

// Invalidate clears all cached expressions for a tenant/resource type. Engine
// calls this when ResourceType records are updated.
func (e *Evaluator) Invalidate(tenantID, resourceType string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	prefix := tenantID + "\x00"
	infix := "\x00" + resourceType + "\x00"
	for k := range e.cache {
		if strings.HasPrefix(k, prefix) && strings.Contains(k, infix) {
			delete(e.cache, k)
		}
	}
}

// Eval walks the expression AST and returns true iff the subject has the
// permission on the object given the relation tuples in store.
func (e *Evaluator) Eval(ctx context.Context, expr Expr, ec EvalContext) (bool, error) {
	if expr == nil {
		return false, nil
	}
	depth := ec.MaxDepth
	if depth <= 0 {
		depth = 10
	}
	return e.walk(ctx, expr, ec, depth)
}

func (e *Evaluator) walk(ctx context.Context, expr Expr, ec EvalContext, depth int) (bool, error) {
	if depth <= 0 {
		return false, nil
	}
	switch v := expr.(type) {
	case *RefExpr:
		// Direct relation match: does (object, relation, subject) exist?
		return e.relStore.CheckDirectRelation(ctx, ec.TenantID, ec.NamespacePath,
			ec.ObjectType, ec.ObjectID, v.Name,
			ec.SubjectType, ec.SubjectID)
	case *OrExpr:
		left, err := e.walk(ctx, v.Left, ec, depth)
		if err != nil {
			return false, err
		}
		if left {
			return true, nil
		}
		return e.walk(ctx, v.Right, ec, depth)
	case *AndExpr:
		left, err := e.walk(ctx, v.Left, ec, depth)
		if err != nil {
			return false, err
		}
		if !left {
			return false, nil
		}
		return e.walk(ctx, v.Right, ec, depth)
	case *NotExpr:
		inner, err := e.walk(ctx, v.Inner, ec, depth)
		if err != nil {
			return false, err
		}
		return !inner, nil
	case *TraverseExpr:
		return e.walkTraversal(ctx, v.Steps, ec, depth)
	}
	return false, nil
}

// walkTraversal evaluates a traversal `parent->read` by:
//
//  1. Listing tuples for relation `parent` on the current object.
//  2. For each resulting object, checking the next step (`read`) on it,
//     which may itself be a relation or a permission expression.
//
// We treat every intermediate step as a relation lookup since tuples are
// the only persistent thing we have at runtime; resolving a step that's
// actually a permission would require recursive evaluation against the
// chained resource type. We support that recursion via a callback the
// engine wires in via WithPermissionResolver.
type permResolver func(ctx context.Context, resourceType, resourceID, permName string, ec EvalContext) (bool, error)

func (e *Evaluator) walkTraversal(ctx context.Context, steps []string, ec EvalContext, depth int) (bool, error) {
	if len(steps) < 2 {
		return false, nil
	}
	// Hop step 0: enumerate (object, relation=steps[0], ?) tuples.
	tuples, err := e.relStore.ListRelationSubjects(ctx, ec.TenantID, ec.NamespacePath,
		ec.ObjectType, ec.ObjectID, steps[0])
	if err != nil {
		return false, err
	}
	for _, t := range tuples {
		// New evaluation context with the hopped object.
		next := ec
		next.ObjectType = t.SubjectType
		next.ObjectID = t.SubjectID

		if len(steps) == 2 {
			// Final step: try direct relation match on the hopped object first.
			ok, err := e.relStore.CheckDirectRelation(ctx, ec.TenantID, ec.NamespacePath,
				next.ObjectType, next.ObjectID, steps[1],
				ec.SubjectType, ec.SubjectID)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
			// Fall through: maybe the final step is a permission expression
			// on the hopped resource type (e.g. `parent->read` where `read`
			// is `viewer or owner` on the parent's type). Recursively evaluate.
			if e.resolve != nil {
				if expr, has := e.resolve(ctx, ec.TenantID, ec.NamespacePath, next.ObjectType, steps[1]); has {
					sub, err := e.walk(ctx, expr, next, depth-1)
					if err != nil {
						return false, err
					}
					if sub {
						return true, nil
					}
				}
			}
			continue
		}
		// Continue hopping with the remaining steps.
		ok, err := e.walkTraversal(ctx, steps[1:], next, depth-1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func cacheKey(tenant, ns, restype, perm string) string {
	return tenant + "\x00" + ns + "\x00" + restype + "\x00" + perm
}
