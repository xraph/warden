// Package api provides HTTP handlers for the Warden authorization engine.
package api

import (
	"net/http"

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
}

// New creates an API from an Engine and a Forge router. Every route is
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

// Handler returns the fully assembled http.Handler with all routes.
func (a *API) Handler() http.Handler {
	if a.router == nil {
		a.router = forge.NewRouter()
	}
	if err := a.RegisterRoutes(a.router); err != nil {
		panic("warden: register routes: " + err.Error())
	}
	return a.router.Handler()
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
