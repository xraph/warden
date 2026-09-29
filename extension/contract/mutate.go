// mutate.go: what every dashboard write does after the store call.
//
// The REST handlers in api/ emit a typed hook and an audit event for each
// mutation, with the caller as the actor. A dashboard write used to skip
// all of it: the store changed, and nothing else heard about it. The
// consequences were an audit plugin that never saw dashboard changes, a
// cache that kept serving an ALLOW for a grant that was gone until its TTL
// ran out, and CreatedBy/UpdatedBy left empty.
//
// This helper duplicates the small emit pattern from api/role_handler.go
// and api/permission_handler.go instead of sharing it. Sharing would need a
// third package both api/ and extension/contract import, for about ten
// lines, and the two call sites differ in what they have in hand (a forge
// context there, a Principal here).
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/plugin"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// viaDashboard is the Actor.Via value for every write that comes through
// this package, so an audit trail can tell a dashboard change from a REST
// one.
const viaDashboard = "dashboard"

// actorFor derives the audit actor from the principal. Callers have already
// passed tenantFrom, which refuses a principal with no user, so a missing
// user here would be a bug. It still yields the zero Actor rather than
// panicking.
func actorFor(p dashcontract.Principal) warden.Actor {
	if p.User == nil {
		return warden.Actor{}
	}
	return warden.Actor{Kind: "user", ID: p.User.Subject, Via: viaDashboard}
}

// withActor returns ctx carrying the principal's Actor, so plugin hooks and
// the check log see who acted.
func withActor(ctx context.Context, p dashcontract.Principal) context.Context {
	return warden.WithActor(ctx, actorFor(p))
}

// emitAudit sends one audit event when the engine has plugins. The cache
// invalidator is one of them whenever a cache is configured, and its
// OnAudit hook flushes the tenant, which is what closes the stale-ALLOW
// window after a dashboard write.
func emitAudit(ctx context.Context, deps Deps, p dashcontract.Principal, action, tenantID, entityID string, entity, before any) {
	pl := deps.Engine.Plugins()
	if pl == nil {
		return
	}
	pl.EmitAudit(ctx, plugin.Event{
		Actor:    actorFor(p),
		At:       time.Now(),
		Action:   action,
		TenantID: tenantID,
		EntityID: entityID,
		Entity:   entity,
		Before:   before,
	})
}
