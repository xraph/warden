package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// AuthorizerFunc decides whether the current caller may perform action on
// resource (a "warden:<entity>" string, e.g. "warden:role"). The default
// implementation, installed when no WithAuthorizer option is given,
// resolves the caller's warden.Actor from context and runs it back
// through the engine as a warden.CheckRequest.
type AuthorizerFunc func(ctx forge.Context, action, resource string) error

// Option configures an API instance.
type Option func(*API)

// WithAuthorizer overrides the API's authorization decision function.
// Mostly useful for tests and for deployments that want a static policy
// instead of routing the decision back through the engine.
func WithAuthorizer(fn AuthorizerFunc) Option {
	return func(a *API) {
		if fn != nil {
			a.authorizer = fn
		}
	}
}

// WithInsecureAllowUnauthenticatedRoutes disables requireIdentity across
// every route, not just the three check endpoints. It exists solely for
// the extension package to pass through when the operator has explicitly
// set auth.require_identity=false and acknowledged the risk via
// extension.WithInsecureAllowUnauthenticatedRoutes; it is deliberately
// not documented as a normal option and should never be reached for by a
// caller wiring api.New directly.
func WithInsecureAllowUnauthenticatedRoutes() Option {
	return func(a *API) { a.skipIdentity = true }
}

// AllowAnonymousChecks lets the three check endpoints (POST
// /v1/authz/check, /v1/authz/enforce, /v1/authz/batch-check) run without a
// resolved caller identity. Every other route, including the AuthZEN
// endpoints, still requires one. Off by default, so an unauthenticated
// caller gets 401 on every route.
func AllowAnonymousChecks() Option {
	return func(a *API) { a.allowAnonymousChecks = true }
}

// anonymousCheckPaths are the request path suffixes exempted from
// requireIdentity (and from authorize) when AllowAnonymousChecks is set.
// Matched by suffix so this keeps working regardless of what base path an
// embedding application mounts the API under.
var anonymousCheckPaths = []string{
	"/v1/authz/check",
	"/v1/authz/enforce",
	"/v1/authz/batch-check",
}

func isAnonymousCheckPath(path string) bool {
	for _, p := range anonymousCheckPaths {
		if strings.HasSuffix(path, p) {
			return true
		}
	}
	return false
}

// requireIdentity rejects any request with no resolvable warden.Actor with
// 401 (forge.Unauthorized), except the anonymous-check paths when
// AllowAnonymousChecks is set.
func (a *API) requireIdentity() forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			if a.skipIdentity {
				return next(ctx)
			}
			if a.allowAnonymousChecks && isAnonymousCheckPath(ctx.Request().URL.Path) {
				return next(ctx)
			}
			if _, ok := warden.ActorFromContext(ctx.Context()); !ok {
				return forge.Unauthorized("warden: authentication required")
			}
			return next(ctx)
		}
	}
}

// requireScope rejects any request whose resolved tenant is empty with
// 400 (forge.BadRequest). Applied uniformly, including to anonymous
// checks: identity and tenant scope are resolved independently, and a
// tenant is still required to know which catalog to evaluate against.
func (a *API) requireScope() forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			_, tenantID := scopeFromForgeContext(ctx)
			if tenantID == "" {
				return forge.BadRequest("warden: tenant is required")
			}
			return next(ctx)
		}
	}
}

// captureRequestIP overlays the caller's IP onto the request context so
// check-log entries and audit events can record it.
func captureRequestIP() forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			if ip := requestIP(ctx); ip != "" {
				ctx.WithContext(warden.WithRequestIP(ctx.Context(), ip))
			}
			return next(ctx)
		}
	}
}

// authorize returns a route-level middleware that authorizes action on
// resource via a.authorizer. Skipped entirely for the anonymous-check
// paths when AllowAnonymousChecks is set: there is no caller identity to
// authorize as there, and the whole point of that option is an open check
// endpoint.
func (a *API) authorize(action, resource string) forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			if a.skipIdentity {
				return next(ctx)
			}
			if a.allowAnonymousChecks && isAnonymousCheckPath(ctx.Request().URL.Path) {
				return next(ctx)
			}
			if err := a.authorizer(ctx, action, resource); err != nil {
				return err
			}
			return next(ctx)
		}
	}
}

// defaultAuthorize is the AuthorizerFunc installed when no WithAuthorizer
// option is given. It resolves the caller's Actor and asks the engine
// whether that actor may perform action on resource, scoped to whatever
// tenant requireScope already validated.
func (a *API) defaultAuthorize(ctx forge.Context, action, resource string) error {
	actor, ok := warden.ActorFromContext(ctx.Context())
	if !ok {
		// requireIdentity always runs first in RegisterRoutes, so this only
		// fires when a caller wires authorize() without it (e.g. a test).
		return forge.Unauthorized("warden: authentication required")
	}
	req := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectKind(actor.Kind), ID: actor.ID},
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resource},
	}
	if err := a.eng.Enforce(ctx.Context(), req); err != nil {
		if errors.Is(err, warden.ErrAccessDenied) {
			return forge.Forbidden(fmt.Sprintf("warden: %s:%s missing permission %s on %s", actor.Kind, actor.ID, action, resource))
		}
		return mapError(err)
	}
	return nil
}
