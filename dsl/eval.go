package dsl

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
)

// CompileExpr parses a textual permission expression into an AST.
// Used by the engine to compile ResourceType.Permissions[].Expression
// at Check time (with caching).
func CompileExpr(file, src string) (Expr, []*Diagnostic) {
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

	// NamespacePaths is the set of namespaces a relation lookup may match —
	// typically the request namespace and its ancestors, so relations cascade
	// like roles and policies. When empty, lookups fall back to the single
	// NamespacePath (see nsList).
	NamespacePaths []string

	ObjectType string
	ObjectID   string

	SubjectType string
	SubjectID   string

	// MaxDepth bounds traversal recursion. The engine sets this from its
	// configured graph walker depth.
	MaxDepth int
}

// nsList returns the namespaces a relation lookup should match. It prefers the
// cascaded NamespacePaths and falls back to the single NamespacePath so an
// EvalContext constructed without the cascade list still works (exact match).
func (ec EvalContext) nsList() []string {
	if len(ec.NamespacePaths) > 0 {
		return ec.NamespacePaths
	}
	return []string{ec.NamespacePath}
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
	cache map[string]exprCacheEntry // keyed by `tenant\x00ns\x00restype\x00perm`
}

// exprCacheEntry pairs a compiled expression with the UpdatedAt timestamp
// of the resource type it was compiled from, so a stale cache entry (the
// resource type's permission expression changed since compilation) can be
// detected and recompiled instead of silently evaluating a check against
// an expression that no longer matches the stored definition.
type exprCacheEntry struct {
	expr      Expr
	updatedAt time.Time
}

// NewEvaluator constructs an evaluator backed by the given relation store.
func NewEvaluator(relStore relation.Store) *Evaluator {
	return &Evaluator{
		relStore: relStore,
		cache:    make(map[string]exprCacheEntry),
	}
}

// WithPermResolver sets the permission resolver used during traversal to
// recursively evaluate permissions on hopped-to resource types.
func (e *Evaluator) WithPermResolver(r PermResolver) *Evaluator {
	e.resolve = r
	return e
}

// CompileAndCache parses the expression for a resource-type permission and
// caches the result. Subsequent Eval calls reuse the AST. It never treats a
// cached entry as stale; callers that know the resource type's UpdatedAt
// should use CompileAndCacheVersioned instead so an edited permission
// expression doesn't keep evaluating against the old AST.
func (e *Evaluator) CompileAndCache(tenantID, ns, resourceType, permName, exprSrc string) (Expr, []*Diagnostic) {
	return e.CompileAndCacheVersioned(tenantID, ns, resourceType, permName, exprSrc, time.Time{})
}

// CompileAndCacheVersioned is CompileAndCache plus a freshness check: a
// cached entry is only reused when updatedAt is zero (freshness unknown —
// same behavior as CompileAndCache) or not newer than the timestamp the
// cached entry was compiled with. A newer updatedAt means the resource
// type's permission definition changed since the AST was cached, so the
// expression is recompiled from exprSrc and the cache entry replaced.
func (e *Evaluator) CompileAndCacheVersioned(tenantID, ns, resourceType, permName, exprSrc string, updatedAt time.Time) (Expr, []*Diagnostic) {
	key := cacheKey(tenantID, ns, resourceType, permName)
	e.mu.RLock()
	if entry, ok := e.cache[key]; ok {
		if updatedAt.IsZero() || !updatedAt.After(entry.updatedAt) {
			e.mu.RUnlock()
			return entry.expr, nil
		}
	}
	e.mu.RUnlock()
	expr, diags := CompileExpr("<inline>", exprSrc)
	if len(diags) > 0 {
		return expr, diags
	}
	e.mu.Lock()
	e.cache[key] = exprCacheEntry{expr: expr, updatedAt: updatedAt}
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

// InvalidateTenant clears every cached expression for a tenant, across
// every resource type. Used when a mutation doesn't carry enough
// information to invalidate a single resource type precisely — e.g. a
// delete audit event, which only carries an EntityID, not the deleted
// resource type's Name (the cache key).
func (e *Evaluator) InvalidateTenant(tenantID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	prefix := tenantID + "\x00"
	for k := range e.cache {
		if strings.HasPrefix(k, prefix) {
			delete(e.cache, k)
		}
	}
}

// invalidatorPlugin invalidates ev's compiled-expression cache whenever a
// "resourcetype.*" mutation is audited, so an edited or deleted permission
// expression takes effect on the very next Check instead of continuing to
// evaluate against a stale cached AST until CompileAndCacheVersioned
// happens to notice via UpdatedAt.
type invalidatorPlugin struct {
	ev *Evaluator
}

// NewInvalidatorPlugin returns a plugin.Plugin that invalidates ev's cache
// on every "resourcetype.*" audit event (see plugin.Event, plugin.Audit).
// Register it on the same engine that uses ev, typically via
// warden.WithPlugin(dsl.NewInvalidatorPlugin(ev)) alongside
// warden.WithExpressionEvaluator wiring an EngineEvaluator backed by ev.
func NewInvalidatorPlugin(ev *Evaluator) plugin.Plugin {
	return &invalidatorPlugin{ev: ev}
}

func (p *invalidatorPlugin) Name() string { return "dsl-expression-cache-invalidator" }

// OnAudit implements plugin.Audit.
func (p *invalidatorPlugin) OnAudit(_ context.Context, ev plugin.Event) error {
	if !strings.HasPrefix(ev.Action, "resourcetype.") {
		return nil
	}
	if rt, ok := ev.Entity.(*resourcetype.ResourceType); ok && rt != nil {
		p.ev.Invalidate(ev.TenantID, rt.Name)
		return nil
	}
	// No typed entity to read a Name from (a delete event only carries an
	// EntityID) — fall back to a full tenant flush so nothing can outlive
	// the resource type that produced it.
	p.ev.InvalidateTenant(ev.TenantID)
	return nil
}

var _ plugin.Audit = (*invalidatorPlugin)(nil)

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
		return e.relStore.CheckDirectRelation(ctx, ec.TenantID, ec.nsList(),
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
func (e *Evaluator) walkTraversal(ctx context.Context, steps []string, ec EvalContext, depth int) (bool, error) {
	if len(steps) < 2 {
		return false, nil
	}
	// Hop step 0: enumerate (object, relation=steps[0], ?) tuples.
	tuples, err := e.relStore.ListRelationSubjects(ctx, ec.TenantID, ec.nsList(),
		ec.ObjectType, ec.ObjectID, steps[0], 0)
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
			ok, err := e.relStore.CheckDirectRelation(ctx, ec.TenantID, ec.nsList(),
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
