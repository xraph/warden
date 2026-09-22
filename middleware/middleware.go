// Package middleware provides HTTP authorization middleware for Warden.
//
// Require, RequireAny and RequireAll are meant to be mounted on an
// embedding application's own routes (not Warden's management API, which
// authenticates and authorizes itself via api.API's own middleware chain).
package middleware

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// Option configures Require, RequireAny and RequireAll.
type Option func(*config)

type config struct {
	allowAnonymous bool
	contextFn      func(forge.Context) map[string]any
}

func newConfig(opts []Option) *config {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// AllowAnonymous lets a request with no resolvable identity through to the
// engine as an explicit "anonymous" user subject, instead of the default
// 401. Off by default: an unauthenticated caller is rejected before the
// engine is ever consulted, so a route can never be reached by a subject
// nobody actually asked for.
func AllowAnonymous() Option {
	return func(c *config) { c.allowAnonymous = true }
}

// WithContext lets a caller inject extra attributes into the
// warden.CheckRequest.Context map built for each request, e.g. business
// context an ABAC policy condition might match on. fn is called once per
// request; a nil return is treated as no extra context.
func WithContext(fn func(forge.Context) map[string]any) Option {
	return func(c *config) { c.contextFn = fn }
}

// anonymousSubject is the subject used when AllowAnonymous is set and no
// identity resolves. It is a fixed, well-known ID rather than whatever a
// caller happened to send, so it can only ever match roles an operator
// explicitly assigned to it.
var anonymousSubject = warden.Subject{Kind: warden.SubjectUser, ID: "anonymous"}

// resolveSubject extracts the caller's subject from context. Currently
// only the Forge user-identity path is implemented (via
// forge.UserIDFromContext, which shares its context key with
// warden.ActorFromContext's fallback chain). Forge does not currently
// expose an API-key subject in context, so that branch is not
// implemented; a caller authenticated only by API key resolves as
// "no identity" here until that lands upstream.
func resolveSubject(ctx forge.Context) (warden.Subject, bool) {
	if userID := forge.UserIDFromContext(ctx.Context()); userID != "" {
		return warden.Subject{Kind: warden.SubjectUser, ID: userID}, true
	}
	return warden.Subject{}, false
}

// captureRequestIP overlays the caller's IP (first hop of
// X-Forwarded-For, else RemoteAddr) onto ctx's request context, so the
// check log entry the engine writes for this Check records it.
func captureRequestIP(ctx forge.Context) {
	ip := requestIP(ctx)
	if ip != "" {
		ctx.WithContext(warden.WithRequestIP(ctx.Context(), ip))
	}
}

func requestIP(ctx forge.Context) string {
	if xff := ctx.Header("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	req := ctx.Request()
	if req == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}

// buildCheckRequest resolves the caller's subject and assembles the
// warden.CheckRequest for one guarded route, or returns ok=false when the
// caller has no identity and AllowAnonymous was not set (the caller
// should respond 401 in that case).
func buildCheckRequest(ctx forge.Context, cfg *config, action, resourceType string) (*warden.CheckRequest, warden.Subject, bool) {
	subject, ok := resolveSubject(ctx)
	if !ok {
		if !cfg.allowAnonymous {
			return nil, warden.Subject{}, false
		}
		subject = anonymousSubject
	}
	captureRequestIP(ctx)
	req := &warden.CheckRequest{
		Subject:  subject,
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resourceType, ID: ctx.Param("id")},
	}
	if cfg.contextFn != nil {
		req.Context = cfg.contextFn(ctx)
	}
	return req, subject, true
}

// Require enforces authorization. It resolves the subject from the
// request context and checks whether the subject can perform the given
// action on the resource type.
func Require(eng *warden.Engine, action, resourceType string, opts ...Option) forge.Middleware {
	cfg := newConfig(opts)
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			req, subject, ok := buildCheckRequest(ctx, cfg, action, resourceType)
			if !ok {
				return forge.Unauthorized("warden: authentication required")
			}
			result, err := eng.Check(ctx.Context(), req)
			if err != nil {
				return storeErrorResponse(ctx, subject, action, resourceType, err)
			}
			if !result.Allowed {
				logDeny(ctx, subject, action, resourceType, result)
				return forge.Forbidden("warden: access denied")
			}
			return next(ctx)
		}
	}
}

// RequireAny allows the request if ANY of the checks pass.
func RequireAny(eng *warden.Engine, checks []warden.CheckRequest, opts ...Option) forge.Middleware {
	cfg := newConfig(opts)
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			subject, ok := resolveSubject(ctx)
			if !ok {
				if !cfg.allowAnonymous {
					return forge.Unauthorized("warden: authentication required")
				}
				subject = anonymousSubject
			}
			captureRequestIP(ctx)

			var lastErr error
			for i := range checks {
				c := checks[i]
				c.Subject = subject
				if cfg.contextFn != nil {
					c.Context = cfg.contextFn(ctx)
				}
				result, err := eng.Check(ctx.Context(), &c)
				if err != nil {
					lastErr = err
					continue
				}
				if result.Allowed {
					return next(ctx)
				}
			}
			if lastErr != nil {
				return storeErrorResponse(ctx, subject, "", "", lastErr)
			}
			logDeny(ctx, subject, "any", "", nil)
			return forge.Forbidden("warden: access denied")
		}
	}
}

// RequireAll allows the request only if ALL checks pass.
func RequireAll(eng *warden.Engine, checks []warden.CheckRequest, opts ...Option) forge.Middleware {
	cfg := newConfig(opts)
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			subject, ok := resolveSubject(ctx)
			if !ok {
				if !cfg.allowAnonymous {
					return forge.Unauthorized("warden: authentication required")
				}
				subject = anonymousSubject
			}
			captureRequestIP(ctx)

			for i := range checks {
				c := checks[i]
				c.Subject = subject
				if cfg.contextFn != nil {
					c.Context = cfg.contextFn(ctx)
				}
				result, err := eng.Check(ctx.Context(), &c)
				if err != nil {
					return storeErrorResponse(ctx, subject, c.Action.Name, c.Resource.Type, err)
				}
				if !result.Allowed {
					logDeny(ctx, subject, c.Action.Name, c.Resource.Type, result)
					return forge.Forbidden("warden: access denied")
				}
			}
			return next(ctx)
		}
	}
}

// storeErrorResponse handles a non-nil error from eng.Check: a tenant
// resolution problem is the caller's fault (400), anything else is
// treated as the authorization store being unavailable (503) and logged
// at Warn so an operator notices the outage rather than mistaking it for
// a wave of legitimate denials.
func storeErrorResponse(ctx forge.Context, subject warden.Subject, action, resourceType string, err error) error {
	if errors.Is(err, warden.ErrTenantRequired) {
		return forge.BadRequest(err.Error())
	}
	logger := forge.LoggerFromContext(ctx.Context())
	if logger != nil {
		logger.Warn("warden: authorization store error",
			forge.F("path", ctx.Request().URL.Path),
			forge.F("subject_kind", string(subject.Kind)),
			forge.F("subject_id", subject.ID),
			forge.F("action", action),
			forge.F("resource_type", resourceType),
			forge.F("error", err.Error()),
		)
	}
	return forge.NewHTTPError(http.StatusServiceUnavailable, "warden: authorization temporarily unavailable")
}

// logDeny logs a denied check at Info, for operators to see traffic
// patterns without treating every deny as an incident (unlike store
// errors, which log at Warn).
func logDeny(ctx forge.Context, subject warden.Subject, action, resourceType string, result *warden.CheckResult) {
	logger := forge.LoggerFromContext(ctx.Context())
	if logger == nil {
		return
	}
	fields := []forge.Field{
		forge.F("subject_kind", string(subject.Kind)),
		forge.F("subject_id", subject.ID),
		forge.F("action", action),
		forge.F("resource_type", resourceType),
	}
	if result != nil {
		fields = append(fields, forge.F("decision", string(result.Decision)))
	}
	logger.Info("warden: access denied", fields...)
}
