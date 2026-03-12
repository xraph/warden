package dashboard

import (
	"context"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/warden"
	"github.com/xraph/warden/dashboard/components"
	"github.com/xraph/warden/plugin"
)

// NewManifest builds a contributor.Manifest for the warden dashboard.
// It starts with the base nav items, widgets, and settings, then merges
// any additional contributions from plugins implementing DashboardPlugin.
func NewManifest(engine *warden.Engine, plugins []plugin.Plugin) *contributor.Manifest {
	m := &contributor.Manifest{
		Name:        "warden",
		DisplayName: "Warden",
		Icon:        "shield-check",
		Version:     "0.1.0",
		Layout:      "extension",
		ShowSidebar: boolPtr(true),
		TopbarConfig: &contributor.TopbarConfig{
			Title:       "Warden",
			LogoIcon:    "shield-check",
			AccentColor: "#f59e0b",
			ShowSearch:  true,
			Actions: []contributor.TopbarAction{
				{Label: "API Docs", Icon: "file-text", Href: "/docs", Variant: "ghost"},
			},
		},
		SidebarFooterContent: components.FooterAPIDocsLink("/docs"),
		Nav:                  baseNav(),
		Widgets:              baseWidgets(),
		Settings:             baseSettings(),
		Capabilities: []string{
			"searchable",
		},
	}

	// Merge plugin-contributed nav items and widgets.
	for _, p := range plugins {
		// DashboardPageContributor provides nav items for pages with route params.
		if dpc, ok := p.(DashboardPageContributor); ok {
			m.Nav = append(m.Nav, dpc.DashboardNavItems()...)
		}

		dp, ok := p.(DashboardPlugin)
		if !ok {
			continue
		}

		for _, pp := range dp.DashboardPages() {
			m.Nav = append(m.Nav, contributor.NavItem{
				Label:    pp.Label,
				Path:     pp.Route,
				Icon:     pp.Icon,
				Group:    "Warden",
				Priority: 10,
			})
		}

		for _, pw := range dp.DashboardWidgets(context.Background()) {
			m.Widgets = append(m.Widgets, contributor.WidgetDescriptor{
				ID:         pw.ID,
				Title:      pw.Title,
				Size:       pw.Size,
				RefreshSec: pw.RefreshSec,
				Group:      "Warden",
			})
		}
	}

	return m
}

// baseNav returns the core navigation items for the warden dashboard.
func baseNav() []contributor.NavItem {
	return []contributor.NavItem{
		// Warden — overview and playground
		{Label: "Overview", Path: "/", Icon: "layout-dashboard", Group: "Warden", Priority: 0},
		{Label: "Playground", Path: "/playground", Icon: "zap", Group: "Warden", Priority: 1},

		// Access Control — RBAC entities
		{Label: "Roles", Path: "/roles", Icon: "shield", Group: "Access Control", Priority: 0},
		{Label: "Permissions", Path: "/permissions", Icon: "key-round", Group: "Access Control", Priority: 1},
		{Label: "Assignments", Path: "/assignments", Icon: "user-check", Group: "Access Control", Priority: 2},

		// Policy & Relations — ABAC and ReBAC
		{Label: "Policies", Path: "/policies", Icon: "file-lock", Group: "Policy & Relations", Priority: 0},
		{Label: "Relations", Path: "/relations", Icon: "git-branch", Group: "Policy & Relations", Priority: 1},
		{Label: "Resource Types", Path: "/resource-types", Icon: "boxes", Group: "Policy & Relations", Priority: 2},

		// Monitoring — audit and logs
		{Label: "Check Logs", Path: "/check-logs", Icon: "scroll-text", Group: "Monitoring", Priority: 0},
	}
}

// baseWidgets returns the core widget descriptors for the warden dashboard.
func baseWidgets() []contributor.WidgetDescriptor {
	return []contributor.WidgetDescriptor{
		{
			ID:          "warden-stats",
			Title:       "Authz Stats",
			Description: "Authorization entity counts",
			Size:        "md",
			RefreshSec:  60,
			Group:       "Warden",
		},
		{
			ID:          "warden-recent-checks",
			Title:       "Recent Checks",
			Description: "Recent authorization check results",
			Size:        "lg",
			RefreshSec:  15,
			Group:       "Warden",
		},
	}
}

// baseSettings returns the core settings descriptors for the warden dashboard.
func baseSettings() []contributor.SettingsDescriptor {
	return []contributor.SettingsDescriptor{
		{
			ID:          "warden-config",
			Title:       "Authorization Settings",
			Description: "Configure authorization engine behavior",
			Group:       "Warden",
			Icon:        "shield-check",
		},
	}
}

func boolPtr(b bool) *bool { return &b }
