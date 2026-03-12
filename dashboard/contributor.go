package dashboard

import (
	"context"
	"fmt"
	"io"

	"github.com/a-h/templ"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/warden"
	"github.com/xraph/warden/dashboard/components"
	"github.com/xraph/warden/dashboard/pages"
	"github.com/xraph/warden/dashboard/settings"
	"github.com/xraph/warden/dashboard/widgets"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
)

// Ensure Contributor implements the required interfaces at compile time.
var _ contributor.LocalContributor = (*Contributor)(nil)

// Contributor implements the dashboard LocalContributor interface for the
// warden extension. It renders pages, widgets, and settings using templ
// components and ForgeUI, and supports plugin-contributed UI sections.
type Contributor struct {
	manifest *contributor.Manifest
	engine   *warden.Engine
	plugins  []plugin.Plugin
}

// New creates a new warden dashboard contributor.
func New(manifest *contributor.Manifest, engine *warden.Engine, plugins []plugin.Plugin) *Contributor {
	return &Contributor{
		manifest: manifest,
		engine:   engine,
		plugins:  plugins,
	}
}

// Manifest returns the contributor manifest.
func (c *Contributor) Manifest() *contributor.Manifest { return c.manifest }

// RenderPage renders a page for the given route.
func (c *Contributor) RenderPage(ctx context.Context, route string, params contributor.Params) (templ.Component, error) {
	s := c.engine.Store()
	if s == nil {
		return nil, fmt.Errorf("warden dashboard: no store configured")
	}

	comp, err := c.renderPageRoute(ctx, route, s, params)
	if err != nil {
		return nil, err
	}
	// Wrap every page in the PathRewriter so hx-get paths (e.g. "/ext/warden/pages/roles/detail")
	// are rewritten to the fully-qualified dashboard extension path at runtime.
	pagesBase := params.BasePath + "/ext/" + c.manifest.Name + "/pages"
	return templ.ComponentFunc(func(tCtx context.Context, w io.Writer) error {
		return components.PathRewriter(pagesBase).Render(templ.WithChildren(tCtx, comp), w)
	}), nil
}

// renderPageRoute dispatches to the correct page renderer based on the page route.
func (c *Contributor) renderPageRoute(ctx context.Context, pageRoute string, s store.Store, params contributor.Params) (templ.Component, error) {
	// Check plugin-contributed pages first (PageContributor for parameterized routes).
	for _, p := range c.plugins {
		if dpc, ok := p.(PageContributor); ok {
			if comp, err := dpc.DashboardRenderPage(ctx, pageRoute, params); err == nil && comp != nil {
				return comp, nil
			}
		}
	}

	// Check plugin-contributed pages (Plugin for simple routes).
	for _, dp := range c.dashboardPlugins() {
		for _, pp := range dp.DashboardPages() {
			if pp.Route == pageRoute {
				return pp.Render(ctx), nil
			}
		}
	}

	switch pageRoute {
	case "/", "":
		return c.renderOverview(ctx, s)
	case "/roles":
		return c.renderRoles(ctx, s, params)
	case "/roles/detail":
		return c.renderRoleDetail(ctx, s, params)
	case "/permissions":
		return c.renderPermissions(ctx, s, params)
	case "/assignments":
		return c.renderAssignments(ctx, s, params)
	case "/relations":
		return c.renderRelations(ctx, s, params)
	case "/policies":
		return c.renderPolicies(ctx, s, params)
	case "/policies/detail":
		return c.renderPolicyDetail(ctx, s, params)
	case "/policies/create":
		return c.renderPolicyForm(ctx, s, params)
	case "/policies/edit":
		return c.renderPolicyForm(ctx, s, params)
	case "/resource-types":
		return c.renderResourceTypes(ctx, s, params)
	case "/resource-types/detail":
		return c.renderResourceTypeDetail(ctx, s, params)
	case "/resource-types/create":
		return c.renderResourceTypeForm(ctx, s)
	case "/check-logs":
		return c.renderCheckLogs(ctx, s, params)
	case "/playground":
		return c.renderPlayground(ctx)
	default:
		return nil, contributor.ErrPageNotFound
	}
}

// RenderWidget renders a widget by ID.
func (c *Contributor) RenderWidget(ctx context.Context, widgetID string) (templ.Component, error) {
	s := c.engine.Store()
	if s == nil {
		return nil, fmt.Errorf("warden dashboard: no store configured")
	}

	// Check plugin-contributed widgets first.
	for _, dp := range c.dashboardPlugins() {
		for _, w := range dp.DashboardWidgets(ctx) {
			if w.ID == widgetID {
				return w.Render(ctx), nil
			}
		}
	}

	switch widgetID {
	case "warden-stats":
		return c.renderStatsWidget(ctx, s)
	case "warden-recent-checks":
		return c.renderRecentChecksWidget(ctx, s)
	default:
		return nil, contributor.ErrWidgetNotFound
	}
}

// RenderSettings renders a settings panel by ID.
func (c *Contributor) RenderSettings(ctx context.Context, settingID string) (templ.Component, error) {
	pluginSettings := c.collectPluginSettings(ctx)

	switch settingID {
	case "warden-config":
		return c.renderSettings(ctx, pluginSettings)
	default:
		return nil, contributor.ErrSettingNotFound
	}
}

// ─── Private Render Helpers ──────────────────────────────────────────────────

func (c *Contributor) renderOverview(ctx context.Context, s store.Store) (templ.Component, error) {
	counts := fetchEntityCounts(ctx, s, "")

	logs, err := fetchCheckLogs(ctx, s, "", 10)
	if err != nil {
		logs = nil
	}

	cfg := c.engine.Config()

	// Fetch roles for the create dialogs on the overview page
	allRoles, _ := fetchRoles(ctx, s, "") //nolint:errcheck // display data

	pluginSections := c.collectPluginSections(ctx)

	return templ.ComponentFunc(func(tCtx context.Context, w io.Writer) error {
		childCtx := templ.WithChildren(tCtx, components.PluginSections(pluginSections))
		return pages.OverviewPage(counts.Roles, counts.Permissions, counts.Assignments, counts.Relations, counts.Policies, counts.ResourceTypes, logs, cfg, allRoles).Render(childCtx, w)
	}), nil
}

func (c *Contributor) renderRoles(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	search := params.QueryParams["search"]
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	roles, total, err := fetchRolesPaginated(ctx, s, "", search, limit, offset)
	if err != nil {
		roles = nil
		total = 0
	}

	rows := enrichRoleRows(ctx, s, roles)

	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.RolesPage(rows, search, pg), nil
}

func (c *Contributor) renderRoleDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	roleIDStr := params.PathParams["id"]
	if roleIDStr == "" {
		roleIDStr = params.QueryParams["id"]
	}
	if roleIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	roleID, err := id.ParseRoleID(roleIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	r, perms, err := fetchRoleWithPermissions(ctx, s, roleID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve role: %w", err)
	}

	childRoles, _ := s.ListChildRoles(ctx, roleID) //nolint:errcheck // display data; nil is acceptable

	// Fetch all roles for parent select and all permissions for attach dialog
	allRoles, _ := fetchRoles(ctx, s, "")       //nolint:errcheck // display data
	allPerms, _ := fetchPermissions(ctx, s, "") //nolint:errcheck // display data

	pluginSections := c.collectRoleDetailSections(ctx, roleID)

	return templ.ComponentFunc(func(tCtx context.Context, w io.Writer) error {
		childCtx := templ.WithChildren(tCtx, components.PluginSections(pluginSections))
		return pages.RoleDetailPage(r, perms, childRoles, allRoles, allPerms).Render(childCtx, w)
	}), nil
}

func (c *Contributor) renderPermissions(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	search := params.QueryParams["search"]
	resource := params.QueryParams["resource"]
	action := params.QueryParams["action"]
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	perms, total, err := fetchPermissionsPaginated(ctx, s, "", search, resource, action, limit, offset)
	if err != nil {
		perms = nil
		total = 0
	}
	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.PermissionsPage(perms, search, resource, action, pg), nil
}

func (c *Contributor) renderAssignments(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	subjectKind := params.QueryParams["subject_kind"]
	subjectID := params.QueryParams["subject_id"]
	roleIDStr := params.QueryParams["role_id"]
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	items, total, err := fetchAssignmentsPaginated(ctx, s, "", subjectKind, subjectID, roleIDStr, limit, offset)
	if err != nil {
		items = nil
		total = 0
	}

	// Fetch roles for the create dialog selectbox
	allRoles, _ := fetchRoles(ctx, s, "") //nolint:errcheck // display data

	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.AssignmentsPage(items, subjectKind, subjectID, roleIDStr, allRoles, pg), nil
}

func (c *Contributor) renderRelations(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	objectType := params.QueryParams["object_type"]
	objectID := params.QueryParams["object_id"]
	rel := params.QueryParams["relation"]
	subjectType := params.QueryParams["subject_type"]
	subjectID := params.QueryParams["subject_id"]
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	items, total, err := fetchRelationsPaginated(ctx, s, "", objectType, objectID, rel, subjectType, subjectID, limit, offset)
	if err != nil {
		items = nil
		total = 0
	}
	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.RelationsPage(items, objectType, rel, subjectType, pg), nil
}

func (c *Contributor) renderPolicies(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	search := params.QueryParams["search"]
	effectStr := params.QueryParams["effect"]
	active := parseBoolParam(params.QueryParams, "active")
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	items, total, err := fetchPoliciesPaginated(ctx, s, "", search, effectStr, active, limit, offset)
	if err != nil {
		items = nil
		total = 0
	}
	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.PoliciesPage(items, search, effectStr, params.QueryParams["active"], pg), nil
}

func (c *Contributor) renderPolicyDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	polIDStr := params.PathParams["id"]
	if polIDStr == "" {
		polIDStr = params.QueryParams["id"]
	}
	if polIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	polID, err := id.ParsePolicyID(polIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	p, err := s.GetPolicy(ctx, polID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve policy: %w", err)
	}

	pluginSections := c.collectPolicyDetailSections(ctx, polID)

	return templ.ComponentFunc(func(tCtx context.Context, w io.Writer) error {
		childCtx := templ.WithChildren(tCtx, components.PluginSections(pluginSections))
		return pages.PolicyDetailPage(p).Render(childCtx, w)
	}), nil
}

func (c *Contributor) renderPolicyForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	polIDStr := params.QueryParams["id"]
	if polIDStr != "" {
		polID, err := id.ParsePolicyID(polIDStr)
		if err != nil {
			return nil, contributor.ErrPageNotFound
		}
		p, err := s.GetPolicy(ctx, polID)
		if err != nil {
			return nil, fmt.Errorf("dashboard: resolve policy for edit: %w", err)
		}
		return pages.PolicyEditPage(p), nil
	}
	return pages.PolicyCreatePage(), nil
}

func (c *Contributor) renderResourceTypes(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	search := params.QueryParams["search"]
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	items, total, err := fetchResourceTypesPaginated(ctx, s, "", search, limit, offset)
	if err != nil {
		items = nil
		total = 0
	}
	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.ResourceTypesPage(items, search, pg), nil
}

func (c *Contributor) renderResourceTypeDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	rtIDStr := params.PathParams["id"]
	if rtIDStr == "" {
		rtIDStr = params.QueryParams["id"]
	}
	if rtIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	rtID, err := id.ParseResourceTypeID(rtIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	rt, err := s.GetResourceType(ctx, rtID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve resource type: %w", err)
	}

	return pages.ResourceTypeDetailPage(rt), nil
}

func (c *Contributor) renderResourceTypeForm(_ context.Context, _ store.Store) (templ.Component, error) {
	return pages.ResourceTypeCreatePage(), nil
}

func (c *Contributor) renderCheckLogs(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	limit := parseIntParam(params.QueryParams, "limit", 50)
	offset := parseIntParam(params.QueryParams, "offset", 0)

	items, total, err := fetchCheckLogsPaginated(ctx, s, "", params.QueryParams, limit, offset)
	if err != nil {
		items = nil
		total = 0
	}
	pg := components.NewPaginationMeta(total, limit, offset)
	return pages.CheckLogsPage(items, params.QueryParams, pg), nil
}

func (c *Contributor) renderPlayground(_ context.Context) (templ.Component, error) {
	return pages.PlaygroundPage(), nil
}

// ─── Widget Render Helpers ───────────────────────────────────────────────────

func (c *Contributor) renderStatsWidget(ctx context.Context, s store.Store) (templ.Component, error) {
	counts := fetchEntityCounts(ctx, s, "")
	return widgets.StatsWidget(counts.Roles, counts.Permissions, counts.Assignments, counts.Relations, counts.Policies, counts.ResourceTypes), nil
}

func (c *Contributor) renderRecentChecksWidget(ctx context.Context, s store.Store) (templ.Component, error) {
	logs, err := fetchCheckLogs(ctx, s, "", 10)
	if err != nil || logs == nil {
		return widgets.RecentChecksWidget(nil), nil
	}
	return widgets.RecentChecksWidget(logs), nil
}

// ─── Settings Render Helper ──────────────────────────────────────────────────

func (c *Contributor) renderSettings(_ context.Context, pluginSettings []templ.Component) (templ.Component, error) {
	cfg := c.engine.Config()

	pluginNames := make([]string, 0, len(c.plugins))
	for _, p := range c.plugins {
		pluginNames = append(pluginNames, p.Name())
	}

	return templ.ComponentFunc(func(tCtx context.Context, w io.Writer) error {
		childCtx := templ.WithChildren(tCtx, components.PluginSections(pluginSettings))
		return settings.ConfigPanel(cfg, pluginNames).Render(childCtx, w)
	}), nil
}

// ─── Plugin Helpers ──────────────────────────────────────────────────────────

// dashboardPlugins returns all registered plugins that implement Plugin.
func (c *Contributor) dashboardPlugins() []Plugin {
	var dps []Plugin
	for _, p := range c.plugins {
		if dp, ok := p.(Plugin); ok {
			dps = append(dps, dp)
		}
	}
	return dps
}

// collectPluginSections gathers rendered templ components from all dashboard plugins.
func (c *Contributor) collectPluginSections(ctx context.Context) []templ.Component {
	var sections []templ.Component
	for _, dp := range c.dashboardPlugins() {
		for _, w := range dp.DashboardWidgets(ctx) {
			sections = append(sections, w.Render(ctx))
		}
	}
	return sections
}

// collectPluginSettings gathers settings panels from all dashboard plugins.
func (c *Contributor) collectPluginSettings(ctx context.Context) []templ.Component {
	var panels []templ.Component
	for _, dp := range c.dashboardPlugins() {
		if panel := dp.DashboardSettingsPanel(ctx); panel != nil {
			panels = append(panels, panel)
		}
	}
	return panels
}

// collectRoleDetailSections gathers role detail sections from plugins implementing RoleDetailContributor.
func (c *Contributor) collectRoleDetailSections(ctx context.Context, roleID id.RoleID) []templ.Component {
	var sections []templ.Component
	for _, p := range c.plugins {
		if rdc, ok := p.(RoleDetailContributor); ok {
			if section := rdc.DashboardRoleDetailSection(ctx, roleID); section != nil {
				sections = append(sections, section)
			}
		}
	}
	return sections
}

// collectPolicyDetailSections gathers policy detail sections from plugins implementing PolicyDetailContributor.
func (c *Contributor) collectPolicyDetailSections(ctx context.Context, policyID id.PolicyID) []templ.Component {
	var sections []templ.Component
	for _, p := range c.plugins {
		if pdc, ok := p.(PolicyDetailContributor); ok {
			if section := pdc.DashboardPolicyDetailSection(ctx, policyID); section != nil {
				sections = append(sections, section)
			}
		}
	}
	return sections
}
