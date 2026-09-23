package contract

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/xraph/warden"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

//go:embed manifest.yaml
var manifestYAML []byte

// contributorName is the join key. The React plugin's `extension` field must
// match it exactly. A mismatch does not error anywhere: the plugin resolves
// to `hidden`, no routes mount, no nav appears, and nothing is logged,
// because a contributor the server never mentioned is an ordinary thing for
// a shell to encounter.
const contributorName = "warden"

// Deps bundles what the contract handlers need at registration time.
type Deps struct {
	// Engine is the live warden engine. Required.
	Engine *warden.Engine

	// DefaultTenantID is the tenant every dashboard request is scoped to
	// when the principal carries no tenant claim. Required for any
	// deployment that wants the dashboard to answer at all today, because
	// nothing populates Principal.Claims yet.
	//
	// Leave it empty in a multi-tenant deployment. Every read then refuses
	// with PERMISSION_DENIED, which is correct: a dashboard that cannot
	// tell which tenant it is looking at must not guess, and the empty
	// string would match every tenant's rows rather than none.
	DefaultTenantID string
}

// Register loads the embedded manifest, validates it, registers the `warden`
// contributor with reg, and binds the handlers against deps.
func Register(
	d *dispatcher.Dispatcher,
	reg dashcontract.Registry,
	wreg dashcontract.WardenRegistry,
	deps Deps,
) error {
	if deps.Engine == nil {
		return fmt.Errorf("warden/contract: Engine is required")
	}

	m, err := loader.Load(bytes.NewReader(manifestYAML), "warden/extension/contract/manifest.yaml")
	if err != nil {
		return fmt.Errorf("warden/contract: load manifest: %w", err)
	}
	if err := loader.Validate(m, wreg); err != nil {
		return fmt.Errorf("warden/contract: validate manifest: %w", err)
	}
	if err := reg.Register(m); err != nil {
		return fmt.Errorf("warden/contract: register manifest: %w", err)
	}

	if err := dispatcher.RegisterQuery(d, contributorName, "config.detail", 1, configDetailHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register config.detail: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "overview.stats", 1, overviewStatsHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register overview.stats: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "overview.recentChecks", 1, overviewRecentChecksHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register overview.recentChecks: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "namespaces.list", 1, namespacesListHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register namespaces.list: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "roles.list", 1, rolesListHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.list: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "roles.detail", 1, rolesDetailHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.detail: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "roles.create", 1, rolesCreateHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.create: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "roles.update", 1, rolesUpdateHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.update: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "roles.delete", 1, rolesDeleteHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.delete: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "roles.attachPermission", 1, rolesAttachPermissionHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.attachPermission: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "roles.detachPermission", 1, rolesDetachPermissionHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.detachPermission: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "roles.setPermissions", 1, rolesSetPermissionsHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register roles.setPermissions: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "permissions.list", 1, permissionsListHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register permissions.list: %w", err)
	}
	if err := dispatcher.RegisterQuery(d, contributorName, "permissions.detail", 1, permissionsDetailHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register permissions.detail: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "permissions.create", 1, permissionsCreateHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register permissions.create: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "permissions.update", 1, permissionsUpdateHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register permissions.update: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "permissions.delete", 1, permissionsDeleteHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register permissions.delete: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "maintenance.run", 1, maintenanceRunHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register maintenance.run: %w", err)
	}
	if err := dispatcher.RegisterCommand(d, contributorName, "maintenance.cacheInvalidate", 1, cacheInvalidateHandler(deps)); err != nil {
		return fmt.Errorf("warden/contract: register maintenance.cacheInvalidate: %w", err)
	}

	return nil
}
