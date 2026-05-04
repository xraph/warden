package extension

// Config holds the Warden extension configuration.
// Fields can be set programmatically via Option functions or loaded from
// YAML configuration files (under "extensions.warden" or "warden" keys).
type Config struct {
	// DisableRoutes prevents HTTP route registration.
	DisableRoutes bool `json:"disable_routes" mapstructure:"disable_routes" yaml:"disable_routes"`

	// DisableMigrate prevents auto-migration on start.
	DisableMigrate bool `json:"disable_migrate" mapstructure:"disable_migrate" yaml:"disable_migrate"`

	// BasePath is the URL prefix for warden routes (default: "/warden").
	BasePath string `json:"base_path" mapstructure:"base_path" yaml:"base_path"`

	// MaxGraphDepth controls the maximum depth for ReBAC graph traversal.
	MaxGraphDepth int `json:"max_graph_depth" mapstructure:"max_graph_depth" yaml:"max_graph_depth"`

	// GroveDatabase is the name of a grove.DB registered in the DI container.
	// When set, the extension resolves this named database and auto-constructs
	// the appropriate store based on the driver type (pg/sqlite/mongo).
	// When empty and WithGroveDatabase was called, the default (unnamed) DB is used.
	GroveDatabase string `json:"grove_database" mapstructure:"grove_database" yaml:"grove_database"`

	// RequireConfig requires config to be present in YAML files.
	// If true and no config is found, Register returns an error.
	RequireConfig bool `json:"-" yaml:"-"`

	// ─── Declarative DSL (.warden) auto-apply ───
	//
	// When DeclarativeOnStart is true, the extension parses + validates +
	// applies the .warden source(s) configured below at Start time, after
	// migrations have run. Applies are idempotent — apps can re-deploy
	// freely without producing drift.

	// DeclarativePath is a single .warden file, directory, or glob pattern
	// to load. When unset, declarative auto-apply is skipped.
	DeclarativePath string `json:"declarative_path" mapstructure:"declarative_path" yaml:"declarative_path"`

	// DeclarativePaths is a list of paths to load (in addition to
	// DeclarativePath). Useful for splitting tenant-root and per-tenant
	// configs across multiple roots.
	DeclarativePaths []string `json:"declarative_paths" mapstructure:"declarative_paths" yaml:"declarative_paths"`

	// DeclarativeOnStart toggles auto-apply at Start time.
	DeclarativeOnStart bool `json:"declarative_on_start" mapstructure:"declarative_on_start" yaml:"declarative_on_start"`

	// DeclarativePrune deletes tenant entries not present in the config.
	// kubectl-style apply with prune. Defaults to false; opt-in only.
	DeclarativePrune bool `json:"declarative_prune" mapstructure:"declarative_prune" yaml:"declarative_prune"`

	// DeclarativeStrict makes startup fail when the apply produces
	// diagnostics. When false (default), errors are logged but startup
	// continues so a misconfigured tenant doesn't crash the app.
	DeclarativeStrict bool `json:"declarative_strict" mapstructure:"declarative_strict" yaml:"declarative_strict"`

	// DeclarativeTenantID overrides any `tenant <id>` declared in source.
	// Useful for multi-tenant deployments where the same source is applied
	// to many tenants.
	DeclarativeTenantID string `json:"declarative_tenant_id" mapstructure:"declarative_tenant_id" yaml:"declarative_tenant_id"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxGraphDepth: 10,
	}
}
