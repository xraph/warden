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
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxGraphDepth: 10,
	}
}
