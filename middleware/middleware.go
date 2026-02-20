// Package middleware provides HTTP authorization middleware for Warden.
package middleware

import (
	"encoding/json"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// Require enforces authorization. It resolves the subject from the request
// context (Authsome user > API key > anonymous) and checks whether
// the subject can perform the given action on the resource type.
func Require(eng *warden.Engine, action, resourceType string) forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			subject := resolveSubject(ctx)
			resourceID := ctx.Param("id")

			err := eng.Enforce(ctx.Context(), &warden.CheckRequest{
				Subject:  subject,
				Action:   warden.Action{Name: action},
				Resource: warden.Resource{Type: resourceType, ID: resourceID},
			})
			if err != nil {
				return denyResponse(ctx)
			}
			return next(ctx)
		}
	}
}

// RequireAny allows the request if ANY of the checks pass.
func RequireAny(eng *warden.Engine, checks ...warden.CheckRequest) forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			subject := resolveSubject(ctx)
			for i := range checks {
				c := checks[i]
				c.Subject = subject
				result, err := eng.Check(ctx.Context(), &c)
				if err == nil && result.Allowed {
					return next(ctx)
				}
			}
			return denyResponse(ctx)
		}
	}
}

// RequireAll allows the request only if ALL checks pass.
func RequireAll(eng *warden.Engine, checks ...warden.CheckRequest) forge.Middleware {
	return func(next forge.Handler) forge.Handler {
		return func(ctx forge.Context) error {
			subject := resolveSubject(ctx)
			for i := range checks {
				c := checks[i]
				c.Subject = subject
				err := eng.Enforce(ctx.Context(), &c)
				if err != nil {
					return denyResponse(ctx)
				}
			}
			return next(ctx)
		}
	}
}

// resolveSubject extracts the subject from context.
// Priority: Forge user ID (from Authsome) → anonymous.
func resolveSubject(ctx forge.Context) warden.Subject {
	if userID := forge.UserIDFromContext(ctx.Context()); userID != "" {
		return warden.Subject{Kind: warden.SubjectUser, ID: userID}
	}
	return warden.Subject{Kind: "unknown", ID: "anonymous"}
}

func denyResponse(ctx forge.Context) error {
	ctx.SetHeader("Content-Type", "application/json")
	ctx.Response().WriteHeader(403)
	return json.NewEncoder(ctx.Response()).Encode(map[string]string{"error": "access denied"})
}
