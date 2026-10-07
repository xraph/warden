// Package contract wires warden into the Forge dashboard's contract path.
// It registers the `warden` contributor with the dashboard's contract
// registry and answers the intents the React plugin reads.
//
// Warden continues to expose its templ pages through DashboardContributor
// while this package grows; the templ dashboard is retired once every
// surface has an equivalent here. See warden/MIGRATION.md for the
// accounting.
package contract

import (
	"errors"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// mapWardenError translates a warden error into the dashboard's canonical
// wire codes.
//
// The two immutability errors map to PERMISSION_DENIED rather than
// BAD_REQUEST on purpose: retyping the input will not help, so it is not
// bad input. Everything that a person can fix by changing what they typed
// is BAD_REQUEST.
func mapWardenError(err error) error {
	if err == nil {
		return nil
	}
	var capErr *assignment.CapBelowMembersError
	var fullErr *assignment.RoleFullError
	switch {
	// Its own text, not err.Error(): a DSL apply wraps it as "update role
	// <slug>: ...", and the page shows the refusal, not the call chain. That
	// holds for roles.update and for the dry run schema.plan and
	// schema.apply share. It carries no details.reason, which is how a page
	// tells it from schema.apply's "schema_changed" CONFLICT. A cap refusal
	// from apply's write pass, after the dry run passed, does not come
	// through here: it is a half apply, INTERNAL with the full chain.
	case errors.As(err, &capErr):
		return &dashcontract.Error{Code: dashcontract.CodeConflict, Message: capErr.Error()}
	// A role at its cap refusing a new member: the same text the REST
	// assignment create returns as 409.
	case errors.As(err, &fullErr):
		return &dashcontract.Error{Code: dashcontract.CodeConflict, Message: fullErr.Error()}
	case errors.Is(err, warden.ErrNotFound):
		return &dashcontract.Error{Code: dashcontract.CodeNotFound, Message: err.Error()}
	// Before ErrAlreadyExists: both are CONFLICT, and details.reason is what
	// tells a page that the record moved under it (reload) from a name that
	// is taken (rename).
	case errors.Is(err, warden.ErrStaleWrite):
		return &dashcontract.Error{
			Code:    dashcontract.CodeConflict,
			Message: staleMessage(err),
			Details: map[string]any{"reason": "stale"},
		}
	case errors.Is(err, warden.ErrAlreadyExists):
		return &dashcontract.Error{Code: dashcontract.CodeConflict, Message: err.Error()}
	case errors.Is(err, warden.ErrSystemRoleImmutable),
		errors.Is(err, warden.ErrSystemPermissionImmutable):
		return &dashcontract.Error{Code: dashcontract.CodePermissionDenied, Message: err.Error()}
	case errors.Is(err, warden.ErrTenantRequired):
		return &dashcontract.Error{
			Code:    dashcontract.CodeBadRequest,
			Message: "no tenant in scope: select a tenant before reading warden data",
		}
	case errors.Is(err, warden.ErrCyclicRoleInheritance),
		errors.Is(err, warden.ErrMaxMembersExceeded),
		errors.Is(err, warden.ErrInvalidCondition):
		return &dashcontract.Error{Code: dashcontract.CodeBadRequest, Message: err.Error()}
	default:
		return &dashcontract.Error{Code: dashcontract.CodeInternal, Message: err.Error()}
	}
}

// staleMessage says why a conditional write was refused. It names no writer:
// the change that moved the version may have come from this dashboard, the
// REST API or a DSL apply. It says to reload the page, not the record: the
// dashboard can hold a cached copy for a while, so opening the policy again
// may show the same old version.
func staleMessage(err error) string {
	if errors.Is(err, warden.ErrPolicyVersionConflict) {
		return "this policy changed after it was opened, so nothing was saved. " +
			"Reload the page to see the current version, then make the change again."
	}
	return "this record changed after it was opened, so nothing was saved. " +
		"Reload the page to see the current version, then make the change again."
}

// requireEngine is the guard every handler opens with.
func requireEngine(deps Deps) error {
	if deps.Engine == nil {
		return &dashcontract.Error{
			Code:    dashcontract.CodeUnavailable,
			Message: "warden engine not configured",
		}
	}
	return nil
}

// tenantFrom resolves the caller's tenant for a contract request.
//
// READ THIS BEFORE CHANGING IT. It is the most dangerous function here.
//
// warden.ScopeFromContext does NOT work on this path. It reads either a
// warden.WithTenant value or forge.ScopeFrom(ctx), and nothing on the
// contract path sets either: grep extensions/dashboard/contract for
// context.WithValue and you will find nothing. A scope helper ported from
// the deleted templ dashboard's contributor (see MIGRATION.md) compiles,
// runs, and silently returns the empty string forever.
//
// The empty string is not a harmless zero. An empty TenantID in a store
// ListFilter matches EVERY tenant's rows rather than none, so a handler
// that resolved "" would serve every tenant's roles, permissions,
// assignments, relations, policies and check logs to whoever opened the
// dashboard. On an authorization check it is worse than a leak: a question
// asked in the wrong scope can return an ALLOW that the real tenant's
// policies would have denied.
//
// So this never defaults to empty. An unresolvable tenant refuses.
//
// Resolution order:
//  0. A signed-in user, or refuse with UNAUTHENTICATED.
//  1. The principal's claims, the canonical per-request surface.
//  2. Deps.DefaultTenantID, for single-tenant deployments that configure it.
//  3. Refuse with PERMISSION_DENIED.
//
// Step 1 returns nothing today. dashauth.UserInfo is built by the auth
// provider, and authsome's userToUserInfo (extension/auth_pages.go) sets no
// Claims at all, so Principal.Claims is empty on every request. The claim
// read is here because it is where the tenant belongs once a tenant
// selector exists, and because reading it costs nothing. Until then a
// multi-tenant deployment either configures DefaultTenantID or gets
// refusals, which is the right behaviour for a dashboard that cannot tell
// which tenant it is looking at.
func tenantFrom(p dashcontract.Principal, deps Deps) (string, error) {
	// Identity comes first. Deps.DefaultTenantID exists so a single-tenant
	// deployment can answer without a tenant claim, not so a request with
	// no user at all can be served under that tenant. Without this line a
	// bare Principal{} resolved to the default and read or wrote the whole
	// catalog.
	if _, err := requireUser(p); err != nil {
		return "", err
	}
	// A claim that is PRESENT but unusable is not the same as no claim, and
	// the difference decides whether the fallback is safe.
	//
	// No claim at all means nothing has been said about the tenant, so a
	// configured default is a reasonable answer. A claim that is present
	// and does not resolve means something tried to say which tenant this
	// is and failed, and answering with a different tenant is how
	// "empty matches everything" gets reintroduced by somebody following
	// this function correctly. So a broken claim refuses.
	if raw, present := p.Claims[tenantClaim]; present {
		s, ok := raw.(string)
		if !ok || s == "" {
			return "", &dashcontract.Error{
				Code: dashcontract.CodePermissionDenied,
				Message: "tenant claim is present but unusable: refusing rather than " +
					"falling back to a different tenant",
			}
		}
		return s, nil
	}
	if deps.DefaultTenantID != "" {
		return deps.DefaultTenantID, nil
	}
	return "", &dashcontract.Error{
		Code: dashcontract.CodePermissionDenied,
		Message: "no tenant in scope: warden cannot tell which tenant this request is for. " +
			"Set warden.dashboard.tenant_id for a single-tenant deployment.",
	}
}

// tenantClaim is the claim key a tenant selector would populate, matching
// the app_id convention authsome uses.
const tenantClaim = "tenant_id"
