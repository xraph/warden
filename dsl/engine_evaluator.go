package dsl

import (
	"context"

	"github.com/xraph/warden"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
)

// engineStore is the minimum surface NewEngineEvaluator needs.
type engineStore interface {
	relation.Store
	resourcetype.Store
}

// EngineEvaluator implements warden.ExpressionEvaluator by looking up the
// resource type's permission expression, compiling+caching it, and
// evaluating against the relation graph.
//
// Wire it via:
//
//	ev := dsl.NewEngineEvaluator(store)
//	eng := warden.NewEngine(warden.WithStore(store), warden.WithExpressionEvaluator(ev))
type EngineEvaluator struct {
	store engineStore
	ev    *Evaluator
}

// NewEngineEvaluator constructs an evaluator backed by the engine's store.
// The store must implement both relation.Store and resourcetype.Store —
// every backend in this repo (memory, sqlite, postgres, mongo) satisfies
// that.
func NewEngineEvaluator(s engineStore) *EngineEvaluator {
	ee := &EngineEvaluator{store: s}
	ee.ev = NewEvaluator(s).WithPermResolver(ee.resolvePerm)
	return ee
}

// resolvePerm implements dsl.PermResolver — looks up the compiled
// expression for a permission on a resource type, walking the namespace
// ancestor chain.
func (e *EngineEvaluator) resolvePerm(ctx context.Context, tenantID, namespacePath, resourceType, permName string) (Expr, bool) {
	rt, ns := e.findResourceType(ctx, tenantID, namespacePath, resourceType)
	if rt == nil {
		return nil, false
	}
	for i := range rt.Permissions {
		if rt.Permissions[i].Name == permName && rt.Permissions[i].Expression != "" {
			expr, errs := e.ev.CompileAndCache(tenantID, ns, resourceType, permName, rt.Permissions[i].Expression)
			if len(errs) > 0 {
				return nil, false
			}
			return expr, true
		}
	}
	return nil, false
}

// EvalPermission implements warden.ExpressionEvaluator.
//
// Walks the namespace ancestor chain looking for a resource type with this
// name, then within that resource type's permissions for one named after
// the request's action. If found and the expression is non-empty, it's
// compiled (cached) and evaluated.
func (e *EngineEvaluator) EvalPermission(
	ctx context.Context,
	tenantID, namespacePath, resourceType, permName, subjectKind, subjectID, resourceID string,
) (bool, error) {
	rt, ns := e.findResourceType(ctx, tenantID, namespacePath, resourceType)
	if rt == nil {
		return false, nil
	}
	var permDef *resourcetype.PermissionDef
	for i := range rt.Permissions {
		if rt.Permissions[i].Name == permName {
			permDef = &rt.Permissions[i]
			break
		}
	}
	if permDef == nil || permDef.Expression == "" {
		return false, nil
	}
	expr, errs := e.ev.CompileAndCache(tenantID, ns, resourceType, permName, permDef.Expression)
	if len(errs) > 0 {
		// Don't fail closed on compile errors — the parser already runs at
		// apply time. Returning false here is safe (the engine will fall
		// through to the graph walker / default deny).
		return false, nil
	}
	return e.ev.Eval(ctx, expr, EvalContext{
		TenantID:      tenantID,
		NamespacePath: namespacePath,
		ObjectType:    resourceType,
		ObjectID:      resourceID,
		SubjectType:   subjectKind,
		SubjectID:     subjectID,
	})
}

// findResourceType walks the namespace ancestor chain looking for a
// resource type with the given name. Returns the resource type and the
// namespace it was found at.
func (e *EngineEvaluator) findResourceType(ctx context.Context, tenantID, ns, name string) (*resourcetype.ResourceType, string) {
	for _, candidate := range warden.AncestorNamespaces(ns) {
		filterNS := candidate
		rts, err := e.store.ListResourceTypes(ctx, &resourcetype.ListFilter{
			TenantID:      tenantID,
			NamespacePath: &filterNS,
		})
		if err != nil {
			continue
		}
		for _, rt := range rts {
			if rt.Name == name {
				return rt, candidate
			}
		}
	}
	return nil, ""
}
