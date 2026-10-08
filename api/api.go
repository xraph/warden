// Package api provides HTTP handlers for the Warden authorization engine.
package api

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// API wires all Warden HTTP handlers together.
type API struct {
	eng    *warden.Engine
	router forge.Router

	authorizer           AuthorizerFunc
	allowAnonymousChecks bool
	skipIdentity         bool

	// handlerMu guards handler and handlerErr, the result of the first
	// Handler call.
	handlerMu  sync.Mutex
	handler    http.Handler
	handlerErr error
}

// New creates an API from an Engine and a Forge router. The router is
// only where Handler registers the routes; pass nil to have Handler
// build a fresh one of its own. RegisterRoutes ignores it and uses the
// router it is given. Every route is
// authenticated and authorized by default: an unauthenticated request
// gets 401, and a caller without the mapped permission gets 403. Pass
// AllowAnonymousChecks() to open the three check endpoints to callers
// with no resolved identity, and WithAuthorizer to replace the default
// engine-backed authorization decision.
func New(eng *warden.Engine, router forge.Router, opts ...Option) *API {
	a := &API{eng: eng, router: router}
	for _, opt := range opts {
		opt(a)
	}
	if a.authorizer == nil {
		a.authorizer = a.defaultAuthorize
	}
	return a
}

// Handler returns the fully assembled http.Handler with all routes, at
// /v1/... and the AuthZEN /access/v1/... on the router passed to New (a
// fresh one when that was nil).
//
// The routes are registered on the first call only, and every later call
// returns the same handler, so calling Handler twice never registers the
// routes twice. When that registration fails, Handler panics with the
// error, and every later call panics with the same error, since the
// router is left half registered.
func (a *API) Handler() http.Handler {
	a.handlerMu.Lock()
	defer a.handlerMu.Unlock()
	if a.handlerErr != nil {
		panic(a.handlerErr.Error())
	}
	if a.handler != nil {
		return a.handler
	}
	if a.router == nil {
		a.router = forge.NewRouter()
	}
	if err := a.RegisterRoutes(a.router); err != nil {
		a.handlerErr = fmt.Errorf("warden: register routes: %w", err)
		panic(a.handlerErr.Error())
	}
	a.handler = a.router.Handler()
	return a.handler
}

// RegisterRoutes registers all API routes into the given Forge router.
//
// Every route is wrapped with identity, scope and IP-capture middleware:
// an unauthenticated request gets 401 (except the three check endpoints
// when AllowAnonymousChecks is set), and a request resolving to no tenant
// gets 400. Per-route authorization (manage/read/check/read_audit against
// "warden:<entity>") is attached individually by each registerXRoutes
// function, since the action and resource differ per route.
//
// The middleware is attached via router.Use, not
// forge.WithGroupMiddleware on a wrapping Group: this router
// implementation does not propagate a Group's middleware down into
// sub-Groups created from it (each registerXRoutes function calls
// router.Group("/v1", ...) again), so wrapping would silently register
// every route with no auth at all. Router.Use does propagate to
// subgroups. Unlike Router.UseGlobal, it also stays scoped to this
// router and its children, rather than leaking onto sibling routes an
// embedding application registered elsewhere on the same top-level
// router.
func (a *API) RegisterRoutes(router forge.Router) error {
	router.Use(captureRequestIP(), a.requireIdentity(), a.requireScope())

	registerers := []func(forge.Router) error{
		a.registerCheckRoutes,
		a.registerAuthZenRoutes,
		a.registerRoleRoutes,
		a.registerPermissionRoutes,
		a.registerAssignmentRoutes,
		a.registerRelationRoutes,
		a.registerPolicyRoutes,
		a.registerResourceTypeRoutes,
		a.registerCheckLogRoutes,
	}
	for _, fn := range registerers {
		if err := fn(router); err != nil {
			return err
		}
	}
	return nil
}
