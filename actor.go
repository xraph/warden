package warden

import (
	"context"

	log "github.com/xraph/go-utils/log"
)

// Actor identifies who or what caused a mutation, for audit trails and the
// plugin Audit hook. It is deliberately small and serializable so it can
// travel through plugin.Event.Actor (typed as `any` there to avoid an
// import cycle).
type Actor struct {
	Kind string `json:"kind"`          // "user", "api_key", "service", "system"
	ID   string `json:"id"`            //
	Via  string `json:"via,omitempty"` // "forge", "declarative", "cli", ""
}

// SystemActor identifies warden itself as the actor, used for internal
// mutations that are not attributable to a caller (maintenance jobs, etc).
var SystemActor = Actor{Kind: "system", ID: "warden", Via: "system"}

type actorContextKey struct{}

// WithActor returns a context carrying an explicit Actor. Takes priority
// over any actor inferred from ActorFromContext's fallback chain.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, a)
}

// ActorFromContext returns the Actor for the current request.
//
// Resolution order:
//  1. An explicit Actor set via WithActor.
//  2. log.UserIDFromContext(ctx), wrapped as {Kind: "user", ID: uid, Via: "forge"}.
//  3. Not found: the zero Actor and false.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	if a, ok := ctx.Value(actorContextKey{}).(Actor); ok {
		return a, true
	}
	if uid := log.UserIDFromContext(ctx); uid != "" {
		return Actor{Kind: "user", ID: uid, Via: "forge"}, true
	}
	return Actor{}, false
}
