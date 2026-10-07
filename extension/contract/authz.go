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
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/xraph/warden"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
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
// because maintenance.run deletes the tenant's expired assignments and its
// check log entries past the retention window, and deleting audit entries
// is not something a role manager should get for free.
var intentPolicies = map[string]intentPolicy{
	"config.detail":         {"read", "warden:config"},
	"overview.stats":        {"read", "warden:overview"},
	"overview.recentChecks": {"read_audit", "warden:check_log"},
	"checkLogs.list":        {"read_audit", "warden:check_log"},
	"checkLogs.detail":      {"read_audit", "warden:check_log"},
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
	// The expansion reads relation tuples and nothing else, so the relation
	// read grant is all it takes.
	"relations.expand": {"read", "warden:relation"},

	// Same resource the REST resource type routes use
	// (api/resourcetype_handler.go), so one grant covers both surfaces.
	"resourceTypes.list":   {"read", "warden:resourcetype"},
	"resourceTypes.detail": {"read", "warden:resourcetype"},
	"resourceTypes.create": {"manage", "warden:resourcetype"},
	"resourceTypes.update": {"manage", "warden:resourcetype"},
	"resourceTypes.delete": {"manage", "warden:resourcetype"},
	// The schema graph reads resource types and nothing else.
	"resourceTypes.graph": {"read", "warden:resourcetype"},

	// Same resource the REST policy routes use, so one grant covers both
	// surfaces. Validating a draft writes nothing, so it is a read too.
	"policies.list":      {"read", "warden:policy"},
	"policies.detail":    {"read", "warden:policy"},
	"policies.validate":  {"read", "warden:policy"},
	"policies.create":    {"manage", "warden:policy"},
	"policies.update":    {"manage", "warden:policy"},
	"policies.setActive": {"manage", "warden:policy"},
	"policies.delete":    {"manage", "warden:policy"},

	"maintenance.run":             {"manage", "warden:maintenance"},
	"maintenance.cacheInvalidate": {"manage", "warden:maintenance"},

	// The playground asks the engine a question, so it needs the same grant
	// a caller needs to run a check. The check it builds is a dry run, and so
	// is authorizing the call, since both intents are queries (see
	// Authorize).
	"playground.explain":    {"check", "warden:authz"},
	"playground.batchCheck": {"check", "warden:authz"},

	// The subject view is reached through its assignments, so the intent
	// needs the assignment read grant. That grant covers the assignments
	// alone: the handler checks read on warden:role, warden:relation and
	// warden:policy itself before it returns those sections, and leaves out
	// the check log, which needs read_audit.
	"subjects.detail": {"read", "warden:assignment"},

	// The schema source carries roles, permissions, policies, resource types
	// and relations. The gate takes one (action, resource) per intent, so it
	// checks warden:role and the handlers check read on the other four
	// through principalHolds, refusing with the first missing grant.
	"schema.export": {"read", "warden:role"},
	"schema.plan":   {"read", "warden:role"},

	// An apply writes all five kinds, so the gate checks manage on
	// warden:role and the handler checks manage on the other four.
	"schema.apply": {"manage", "warden:role"},
}

// commandIntents maps every intent in warden's manifest to whether it is a
// command. Authorize logs a command's check and dry-runs a query's, and it
// reads the kind here, from the manifest warden ships, never from the
// request envelope, whose kind the browser chose. Parsed once.
var commandIntents = sync.OnceValues(func() (map[string]bool, error) {
	m, err := loader.Load(bytes.NewReader(manifestYAML), "warden/extension/contract/manifest.yaml")
	if err != nil {
		return nil, err
	}
	kinds := make(map[string]bool, len(m.Intents))
	for _, in := range m.Intents {
		kinds[in.Name] = in.Kind == dashcontract.IntentKindCommand
	}
	return kinds, nil
})

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
//
// A command's check is a real one: it writes a check log row and fires
// hooks, allowed or denied, because a write is rare and is what an auditor
// looks for. A query's check is a dry run. Every page view and every poll
// is a query, and logging them would fill the check log an operator browses
// with the dashboard's own reads. The cost is that a denied read leaves no
// check log row; forge's transport answers it with a 403 and audits nothing.
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
	if _, err := requireUser(p); err != nil {
		return deny("authentication required"), nil //nolint:nilerr // a refusal is a decision, not a failure
	}
	tenantID, err := tenantFrom(p, a.deps)
	if err != nil {
		return deny("no tenant in scope"), nil //nolint:nilerr // a refusal is a decision, not a failure
	}

	kinds, err := commandIntents()
	if err != nil {
		return deny("authorization unavailable"), fmt.Errorf("warden/contract: load manifest kinds: %w", err)
	}
	logged, ok := kinds[act.Intent]
	if !ok {
		// intentPolicies names an intent the manifest does not. The guards in
		// authz_test.go keep the two in step, so this is a build gone wrong.
		return deny("no authorization policy for intent " + act.Intent), nil
	}

	held, err := principalHolds(ctx, a.deps.Engine, p, tenantID, pol.action, pol.resource, logged)
	if err != nil {
		// The engine could not decide. Deny, and return the error so the
		// transport records it, but keep the cause out of the reason: that
		// text goes back to the browser.
		return deny("authorization unavailable"), fmt.Errorf("warden/contract: authorize %s: %w", act.Intent, err)
	}
	if !held {
		return deny(fmt.Sprintf("missing permission %s on %s", pol.action, pol.resource)), nil
	}
	return dashcontract.Decision{Allow: true}, nil
}

// principalHolds reports whether the principal's signed-in user holds action
// on resource in tenantID. It is the one question Authorize asks, and a
// handler that returns more than its intent's grant covers asks it again
// for each extra grant, so the two can never drift apart.
//
// The check runs through Enforce, with the user as a SubjectUser, in the
// resolved tenant. With logged it is a real check that writes a check log
// row and fires hooks; without it, a dry run that does neither and skips the
// result cache. The decision is the same either way. Pass logged for a
// command and not for a query, as Authorize does. ErrAccessDenied means no.
// A principal with no user, and any other engine error, is an error: the
// caller fails closed on it.
func principalHolds(ctx context.Context, eng *warden.Engine, p dashcontract.Principal, tenantID, action, resource string, logged bool) (bool, error) {
	subject, err := requireUser(p)
	if err != nil {
		return false, err
	}
	req := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: subject},
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resource},
	}
	opts := []warden.CallOption{warden.WithCallTenantID(tenantID)}
	if !logged {
		opts = append(opts, warden.WithCallDryRun())
	}
	if err := eng.Enforce(ctx, req, opts...); err != nil {
		if errors.Is(err, warden.ErrAccessDenied) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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
