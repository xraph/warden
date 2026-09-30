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
// func directly, once as a signed-in user with no tenant and no
// Deps.DefaultTenantID, once as an anonymous caller with one. That table's size is checked against
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
	"github.com/xraph/warden/id"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
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
	call   func(deps Deps, p dashcontract.Principal) error
}

var tenantEnforcedHandlers = []tenantEnforcementCase{
	{"overview.stats", func(deps Deps, p dashcontract.Principal) error {
		_, err := overviewStatsHandler(deps)(context.Background(), struct{}{}, p)
		return err
	}},
	{"overview.recentChecks", func(deps Deps, p dashcontract.Principal) error {
		_, err := overviewRecentChecksHandler(deps)(context.Background(), RecentChecksInput{}, p)
		return err
	}},
	{"checkLogs.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := checkLogsListHandler(deps)(context.Background(), CheckLogsListInput{}, p)
		return err
	}},
	{"checkLogs.detail", func(deps Deps, p dashcontract.Principal) error {
		_, err := checkLogsDetailHandler(deps)(context.Background(), CheckLogDetailInput{}, p)
		return err
	}},
	{"namespaces.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := namespacesListHandler(deps)(context.Background(), struct{}{}, p)
		return err
	}},
	{"roles.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesListHandler(deps)(context.Background(), RolesListInput{}, p)
		return err
	}},
	{"roles.detail", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesDetailHandler(deps)(context.Background(), RoleDetailInput{}, p)
		return err
	}},
	{"roles.create", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesCreateHandler(deps)(context.Background(), RoleCreateInput{}, p)
		return err
	}},
	{"roles.update", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesUpdateHandler(deps)(context.Background(), RoleUpdateInput{}, p)
		return err
	}},
	{"roles.delete", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesDeleteHandler(deps)(context.Background(), RoleDeleteInput{}, p)
		return err
	}},
	{"roles.attachPermission", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesAttachPermissionHandler(deps)(context.Background(), RolePermissionInput{}, p)
		return err
	}},
	{"roles.detachPermission", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesDetachPermissionHandler(deps)(context.Background(), RolePermissionInput{}, p)
		return err
	}},
	{"roles.setPermissions", func(deps Deps, p dashcontract.Principal) error {
		_, err := rolesSetPermissionsHandler(deps)(context.Background(), RoleSetPermissionsInput{}, p)
		return err
	}},
	{"permissions.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := permissionsListHandler(deps)(context.Background(), PermissionsListInput{}, p)
		return err
	}},
	{"permissions.detail", func(deps Deps, p dashcontract.Principal) error {
		_, err := permissionsDetailHandler(deps)(context.Background(), PermissionDetailInput{}, p)
		return err
	}},
	{"permissions.create", func(deps Deps, p dashcontract.Principal) error {
		_, err := permissionsCreateHandler(deps)(context.Background(), PermissionCreateInput{}, p)
		return err
	}},
	{"permissions.update", func(deps Deps, p dashcontract.Principal) error {
		_, err := permissionsUpdateHandler(deps)(context.Background(), PermissionUpdateInput{}, p)
		return err
	}},
	{"permissions.delete", func(deps Deps, p dashcontract.Principal) error {
		_, err := permissionsDeleteHandler(deps)(context.Background(), PermissionDeleteInput{}, p)
		return err
	}},
	{"assignments.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := assignmentsListHandler(deps)(context.Background(), AssignmentsListInput{}, p)
		return err
	}},
	{"assignments.expiring", func(deps Deps, p dashcontract.Principal) error {
		_, err := assignmentsExpiringHandler(deps)(context.Background(), ExpiringInput{}, p)
		return err
	}},
	{"assignments.create", func(deps Deps, p dashcontract.Principal) error {
		_, err := assignmentsCreateHandler(deps)(context.Background(), AssignmentCreateInput{}, p)
		return err
	}},
	{"assignments.delete", func(deps Deps, p dashcontract.Principal) error {
		_, err := assignmentsDeleteHandler(deps)(context.Background(), AssignmentDeleteInput{}, p)
		return err
	}},
	{"relations.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := relationsListHandler(deps)(context.Background(), RelationsListInput{}, p)
		return err
	}},
	{"relations.create", func(deps Deps, p dashcontract.Principal) error {
		_, err := relationsCreateHandler(deps)(context.Background(), RelationCreateInput{}, p)
		return err
	}},
	{"relations.delete", func(deps Deps, p dashcontract.Principal) error {
		_, err := relationsDeleteHandler(deps)(context.Background(), RelationDeleteInput{}, p)
		return err
	}},
	{"resourceTypes.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := resourceTypesListHandler(deps)(context.Background(), ResourceTypesListInput{}, p)
		return err
	}},
	{"resourceTypes.detail", func(deps Deps, p dashcontract.Principal) error {
		_, err := resourceTypesDetailHandler(deps)(context.Background(), ResourceTypeDetailInput{}, p)
		return err
	}},
	{"resourceTypes.create", func(deps Deps, p dashcontract.Principal) error {
		_, err := resourceTypesCreateHandler(deps)(context.Background(), ResourceTypeCreateInput{}, p)
		return err
	}},
	{"resourceTypes.update", func(deps Deps, p dashcontract.Principal) error {
		_, err := resourceTypesUpdateHandler(deps)(context.Background(), ResourceTypeUpdateInput{}, p)
		return err
	}},
	{"resourceTypes.delete", func(deps Deps, p dashcontract.Principal) error {
		_, err := resourceTypesDeleteHandler(deps)(context.Background(), ResourceTypeDeleteInput{}, p)
		return err
	}},
	{"policies.list", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesListHandler(deps)(context.Background(), PoliciesListInput{}, p)
		return err
	}},
	{"policies.detail", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesDetailHandler(deps)(context.Background(), PolicyDetailInput{ID: id.NewPolicyID().String()}, p)
		return err
	}},
	{"policies.validate", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesValidateHandler(deps)(context.Background(), PolicyDraft{}, p)
		return err
	}},
	{"policies.create", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesCreateHandler(deps)(context.Background(), PolicyCreateInput{}, p)
		return err
	}},
	{"policies.update", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesUpdateHandler(deps)(context.Background(), PolicyUpdateInput{ID: id.NewPolicyID().String()}, p)
		return err
	}},
	{"policies.setActive", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesSetActiveHandler(deps)(context.Background(), PolicySetActiveInput{ID: id.NewPolicyID().String()}, p)
		return err
	}},
	{"policies.delete", func(deps Deps, p dashcontract.Principal) error {
		_, err := policiesDeleteHandler(deps)(context.Background(), PolicyDeleteInput{ID: id.NewPolicyID().String()}, p)
		return err
	}},
	{"maintenance.run", func(deps Deps, p dashcontract.Principal) error {
		_, err := maintenanceRunHandler(deps)(context.Background(), struct{}{}, p)
		return err
	}},
	{"maintenance.cacheInvalidate", func(deps Deps, p dashcontract.Principal) error {
		_, err := cacheInvalidateHandler(deps)(context.Background(), CacheInvalidateInput{}, p)
		return err
	}},
	{"playground.explain", func(deps Deps, p dashcontract.Principal) error {
		_, err := playgroundExplainHandler(deps)(context.Background(), PlaygroundExplainInput{}, p)
		return err
	}},
	{"playground.batchCheck", func(deps Deps, p dashcontract.Principal) error {
		_, err := playgroundBatchHandler(deps)(context.Background(), PlaygroundBatchInput{}, p)
		return err
	}},
	{"subjects.detail", func(deps Deps, p dashcontract.Principal) error {
		_, err := subjectsDetailHandler(deps)(context.Background(), SubjectDetailInput{}, p)
		return err
	}},
	{"schema.export", func(deps Deps, p dashcontract.Principal) error {
		_, err := schemaExportHandler(deps)(context.Background(), SchemaExportInput{}, p)
		return err
	}},
	{"schema.plan", func(deps Deps, p dashcontract.Principal) error {
		_, err := schemaPlanHandler(deps)(context.Background(), SchemaPlanInput{}, p)
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

			err := tc.call(deps, signedInNoTenant())
			if err == nil {
				t.Fatalf("%s: a signed-in principal with no tenant claim and no DefaultTenantID was not refused; a handler that reaches "+
					"the store with an empty tenant ID matches every tenant's rows instead of none", tc.intent)
			}
			var ce *dashcontract.Error
			if !errors.As(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
				t.Fatalf("%s: want a CodePermissionDenied refusal from tenantFrom, got %v", tc.intent, err)
			}
		})
	}
}

// TestHandlers_RefuseAnAnonymousCallerEvenWithADefaultTenant is the C1
// regression. Deps.DefaultTenantID is a convenience for single-tenant
// deployments, and it used to make a bare Principal{} (no user at all)
// resolve to a real tenant, so a caller the dashboard never authenticated
// could read and write that tenant's catalog. Every handler except the
// tenant-free config.detail must refuse before it touches the store.
func TestHandlers_RefuseAnAnonymousCallerEvenWithADefaultTenant(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	deps := Deps{Engine: eng, DefaultTenantID: "t1"}

	for _, tc := range tenantEnforcedHandlers {
		tc := tc
		t.Run(tc.intent, func(t *testing.T) {
			err := tc.call(deps, dashcontract.Principal{})
			if err == nil {
				t.Fatalf("%s: an anonymous principal was served under DefaultTenantID", tc.intent)
			}
			var ce *dashcontract.Error
			if !errors.As(err, &ce) || ce.Code != dashcontract.CodeUnauthenticated {
				t.Fatalf("%s: want CodeUnauthenticated, got %v", tc.intent, err)
			}
		})
	}
}

func TestTenantFromRefusesAUserWithNoSubject(t *testing.T) {
	deps := Deps{DefaultTenantID: "t1"}
	p := dashcontract.Principal{User: &dashauth.UserInfo{}}
	if _, err := tenantFrom(p, deps); err == nil {
		t.Fatal("a user with an empty subject must not resolve a tenant")
	}
}
