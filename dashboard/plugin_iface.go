package dashboard

import (
	"context"

	"github.com/a-h/templ"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/warden/id"
)

// PluginWidget describes a widget contributed by a warden plugin.
type PluginWidget struct {
	ID         string
	Title      string
	Size       string // "sm", "md", "lg"
	RefreshSec int
	Render     func(ctx context.Context) templ.Component
}

// PluginPage describes an extra page route contributed by a plugin.
type PluginPage struct {
	Route  string // e.g. "/audit-export"
	Label  string // nav label
	Icon   string // lucide icon name
	Render func(ctx context.Context) templ.Component
}

// DashboardPlugin is optionally implemented by warden plugins
// to contribute UI sections to the warden dashboard contributor.
// When plugins implement this interface, their pages, widgets, and
// settings panels are automatically merged into the dashboard.
type DashboardPlugin interface {
	// DashboardWidgets returns widgets this plugin contributes.
	DashboardWidgets(ctx context.Context) []PluginWidget
	// DashboardSettingsPanel returns a settings templ component, or nil.
	DashboardSettingsPanel(ctx context.Context) templ.Component
	// DashboardPages returns extra page routes this plugin handles.
	DashboardPages() []PluginPage
}

// RoleDetailContributor is optionally implemented by plugins that want to
// contribute a section to the role detail page.
type RoleDetailContributor interface {
	DashboardRoleDetailSection(ctx context.Context, roleID id.RoleID) templ.Component
}

// PolicyDetailContributor is optionally implemented by plugins that want to
// contribute a section to the policy detail page.
type PolicyDetailContributor interface {
	DashboardPolicyDetailSection(ctx context.Context, policyID id.PolicyID) templ.Component
}

// DashboardPageContributor is an enhanced interface for plugins that need
// access to route parameters when rendering dashboard pages.
type DashboardPageContributor interface {
	// DashboardNavItems returns navigation items this plugin contributes.
	DashboardNavItems() []contributor.NavItem
	// DashboardRenderPage renders a page for the given route with params.
	// Returns (nil, ErrPageNotFound) if the route is not handled by this plugin.
	DashboardRenderPage(ctx context.Context, route string, params contributor.Params) (templ.Component, error)
}

// Context keys for embedding tenant ID in context.
type tenantIDContextKey struct{}

// WithTenantID returns a context with the tenant ID embedded.
// Dashboard plugins can extract this via TenantIDFromContext to scope queries.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

// TenantIDFromContext extracts the tenant ID from context, if present.
func TenantIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantIDContextKey{}).(string)
	return v, ok
}
