// handlers_tenant_test.go: a generic guard against a handler that forgets to
// resolve a tenant before touching the store.
//
// tenantFrom is sound today: every handler calls it and uses the resolved
// id. The risk is what comes next. Plans 2 through 6 add roughly forty more
// intents to this package, and a handler that skips tenantFrom and hands
// the store a bare filter still compiles, still passes a single-tenant
// test, and serves every tenant's rows, because an empty TenantID in a
// store ListFilter matches everything rather than nothing (see the comment
// on tenantFrom in errors.go).
//
// The dispatcher exposes no way to list registered handlers, so this test
// enumerates them itself in tenantEnforcedHandlers and invokes each handler
// func directly with a bare dashcontract.Principal{} and an empty
// Deps.DefaultTenantID. That table's size is checked against
// handlerIntentsFromSource (shared with manifest_test.go, which already
// parses contract.go's real dispatcher.Register* calls), so a new handler
// added to contract.go without a matching table entry here fails the count
// check rather than silently going untested.
package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// tenantExemptIntent is config.detail: it reaches no store (it reports the
// engine's static Config) and deliberately answers without a tenant. Naming
// the exemption here, rather than just leaving it out of the table below,
// keeps it a visible decision instead of something that looks identical to
// an oversight.
const tenantExemptIntent = "config.detail"

// tenantEnforcementCase invokes one handler with a bare principal and
// returns whatever error it produced (nil if it did not refuse).
type tenantEnforcementCase struct {
	intent string
	call   func(deps Deps) error
}

var tenantEnforcedHandlers = []tenantEnforcementCase{
	{"overview.stats", func(deps Deps) error {
		_, err := overviewStatsHandler(deps)(context.Background(), struct{}{}, dashcontract.Principal{})
		return err
	}},
	{"overview.recentChecks", func(deps Deps) error {
		_, err := overviewRecentChecksHandler(deps)(context.Background(), RecentChecksInput{}, dashcontract.Principal{})
		return err
	}},
	{"namespaces.list", func(deps Deps) error {
		_, err := namespacesListHandler(deps)(context.Background(), struct{}{}, dashcontract.Principal{})
		return err
	}},
	{"roles.list", func(deps Deps) error {
		_, err := rolesListHandler(deps)(context.Background(), RolesListInput{}, dashcontract.Principal{})
		return err
	}},
	{"roles.detail", func(deps Deps) error {
		_, err := rolesDetailHandler(deps)(context.Background(), RoleDetailInput{}, dashcontract.Principal{})
		return err
	}},
	{"maintenance.run", func(deps Deps) error {
		_, err := maintenanceRunHandler(deps)(context.Background(), struct{}{}, dashcontract.Principal{})
		return err
	}},
	{"maintenance.cacheInvalidate", func(deps Deps) error {
		_, err := cacheInvalidateHandler(deps)(context.Background(), CacheInvalidateInput{}, dashcontract.Principal{})
		return err
	}},
}

func TestHandlers_RefuseWithoutTenant(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	deps := Deps{Engine: eng} // DefaultTenantID left empty on purpose.

	registered := handlerIntentsFromSource(t)
	wantCases := len(registered) - 1 // every registered handler except the one named exemption
	if len(tenantEnforcedHandlers) != wantCases {
		t.Fatalf("tenantEnforcedHandlers has %d entries, want %d: contract.go registers %d handlers and %q is the "+
			"only named exemption, so every other registered intent must appear in this table",
			len(tenantEnforcedHandlers), wantCases, len(registered), tenantExemptIntent)
	}
	if _, ok := registered[tenantExemptIntent]; !ok {
		t.Fatalf("exempt intent %q is not registered in contract.go; update tenantExemptIntent", tenantExemptIntent)
	}

	seen := make(map[string]bool, len(tenantEnforcedHandlers))
	for _, tc := range tenantEnforcedHandlers {
		tc := tc
		t.Run(tc.intent, func(t *testing.T) {
			if seen[tc.intent] {
				t.Fatalf("intent %q listed twice in tenantEnforcedHandlers", tc.intent)
			}
			seen[tc.intent] = true
			if _, ok := registered[tc.intent]; !ok {
				t.Fatalf("table references intent %q, which contract.go does not register", tc.intent)
			}
			if tc.intent == tenantExemptIntent {
				t.Fatalf("exempt intent %q must not also appear in tenantEnforcedHandlers", tc.intent)
			}

			err := tc.call(deps)
			if err == nil {
				t.Fatalf("%s: a bare Principal{} with no DefaultTenantID was not refused; a handler that reaches "+
					"the store with an empty tenant ID matches every tenant's rows instead of none", tc.intent)
			}
			var ce *dashcontract.Error
			if !errors.As(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
				t.Fatalf("%s: want a CodePermissionDenied refusal from tenantFrom, got %v", tc.intent, err)
			}
		})
	}
}
