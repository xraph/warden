// authz.go: the authorization decision in front of every dashboard intent.
//
// The REST API refuses a caller with no identity, then asks the engine
// whether that caller holds the permission the route maps to (see
// api/auth.go, defaultAuthorize). The dashboard contract path is a second
// door onto the same mutations, and it had neither step: an empty
// `requires` predicate allows everyone in Forge's contract transport,
// including a request with no user at all, and the dashboard's own auth
// middleware never blocks. So this file puts the REST model on the contract
// path.
//
// Every intent in manifest.yaml declares `requires: { warden: warden.engine }`.
// Forge's transport runs that delegate after the (empty) boolean predicate
// and before the dispatcher, and treats an error or a non-allow decision as
// a 403. The delegate below refuses anything it cannot positively identify
// and authorize.
package contract

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/warden"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// wardenDelegateName is the name the manifest's `requires.warden` entries
// use and Register binds the engine authorizer under.
const wardenDelegateName = "warden.engine"

// intentPolicy is the (action, resource) pair a caller must hold to run one
// intent. The resource strings are the same "warden:<entity>" values the
// REST routes use, so one grant covers both surfaces.
type intentPolicy struct {
	action   string
	resource string
}

// intentPolicies maps every manifest intent to what it requires. An intent
// missing from this table is refused, so adding a handler without deciding
// who may call it fails closed. TestEveryIntentIsGatedByTheEngineDelegate
// keeps this table, the manifest and the handler registrations in step.
//
// Reads map to "read" (or "read_audit" for the check log, as in the REST
// API). The overview counters and the namespace list summarize every entity
// kind at once, so they sit behind their own "warden:overview" read rather
// than borrowing one entity's grant. maintenance.run and
// maintenance.cacheInvalidate get their own "warden:maintenance" resource
// because maintenance.run is engine-wide: it purges expired assignments
// across every tenant, which is not something a role manager should get for
// free.
var intentPolicies = map[string]intentPolicy{
	"config.detail":         {"read", "warden:config"},
	"overview.stats":        {"read", "warden:overview"},
	"overview.recentChecks": {"read_audit", "warden:check_log"},
	"namespaces.list":       {"read", "warden:overview"},

	"roles.list":             {"read", "warden:role"},
	"roles.detail":           {"read", "warden:role"},
	"roles.create":           {"manage", "warden:role"},
	"roles.update":           {"manage", "warden:role"},
	"roles.delete":           {"manage", "warden:role"},
	"roles.attachPermission": {"manage", "warden:role"},
	"roles.detachPermission": {"manage", "warden:role"},
	"roles.setPermissions":   {"manage", "warden:role"},

	"permissions.list":   {"read", "warden:permission"},
	"permissions.detail": {"read", "warden:permission"},
	"permissions.create": {"manage", "warden:permission"},
	"permissions.update": {"manage", "warden:permission"},
	"permissions.delete": {"manage", "warden:permission"},

	// Same resource the REST assignment routes use (api/assignment_handler.go),
	// so one grant covers both surfaces. The expiring feed is a read.
	"assignments.list":     {"read", "warden:assignment"},
	"assignments.expiring": {"read", "warden:assignment"},
	"assignments.create":   {"manage", "warden:assignment"},
	"assignments.delete":   {"manage", "warden:assignment"},

	// Same resource the REST relation routes use (api/relation_handler.go).
	"relations.list":   {"read", "warden:relation"},
	"relations.create": {"manage", "warden:relation"},
	"relations.delete": {"manage", "warden:relation"},

	// Same resource the REST resource type routes use
	// (api/resourcetype_handler.go), so one grant covers both surfaces.
	"resourceTypes.list":   {"read", "warden:resourcetype"},
	"resourceTypes.detail": {"read", "warden:resourcetype"},
	"resourceTypes.create": {"manage", "warden:resourcetype"},
	"resourceTypes.update": {"manage", "warden:resourcetype"},
	"resourceTypes.delete": {"manage", "warden:resourcetype"},

	"maintenance.run":             {"manage", "warden:maintenance"},
	"maintenance.cacheInvalidate": {"manage", "warden:maintenance"},
}

// engineAuthorizer is the dashcontract.Warden the manifest delegates to.
type engineAuthorizer struct {
	deps Deps
}

func newEngineAuthorizer(deps Deps) dashcontract.Warden {
	return &engineAuthorizer{deps: deps}
}

func deny(reason string) dashcontract.Decision {
	return dashcontract.Decision{Allow: false, Reason: reason}
}

// Authorize implements dashcontract.Warden. It fails closed: a nil user, an
// empty subject, an unresolvable tenant, an intent it has no policy for, a
// foreign contributor, a missing engine and any engine error all deny.
func (a *engineAuthorizer) Authorize(ctx context.Context, p dashcontract.Principal, act dashcontract.Action) (dashcontract.Decision, error) {
	if a.deps.Engine == nil {
		return deny("warden engine not configured"), errors.New("warden/contract: engine not configured")
	}
	if act.Contributor != contributorName {
		return deny("not a warden intent"), nil
	}
	pol, ok := intentPolicies[act.Intent]
	if !ok {
		return deny("no authorization policy for intent " + act.Intent), nil
	}
	subject, err := requireUser(p)
	if err != nil {
		return deny("authentication required"), nil //nolint:nilerr // a refusal is a decision, not a failure
	}
	tenantID, err := tenantFrom(p, a.deps)
	if err != nil {
		return deny("no tenant in scope"), nil //nolint:nilerr // a refusal is a decision, not a failure
	}

	req := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: subject},
		Action:   warden.Action{Name: pol.action},
		Resource: warden.Resource{Type: pol.resource},
	}
	if err := a.deps.Engine.Enforce(ctx, req, warden.WithCallTenantID(tenantID)); err != nil {
		if errors.Is(err, warden.ErrAccessDenied) {
			return deny(fmt.Sprintf("missing permission %s on %s", pol.action, pol.resource)), nil
		}
		// The engine could not decide. Deny, and return the error so the
		// transport records it, but keep the cause out of the reason: that
		// text goes back to the browser.
		return deny("authorization unavailable"), fmt.Errorf("warden/contract: authorize %s: %w", act.Intent, err)
	}
	return dashcontract.Decision{Allow: true}, nil
}

// requireUser returns the caller's subject, or an UNAUTHENTICATED error
// when the request carries no signed-in user.
func requireUser(p dashcontract.Principal) (string, error) {
	if p.User == nil || p.User.Subject == "" {
		return "", &dashcontract.Error{
			Code:    dashcontract.CodeUnauthenticated,
			Message: "warden: authentication required",
		}
	}
	return p.User.Subject, nil
}
