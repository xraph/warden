package extension

import (
	"fmt"
	"time"

	"github.com/xraph/warden"
)

// AuthConfig controls how the extension authenticates and authorizes
// callers of the warden management/decision HTTP API.
type AuthConfig struct {
	// RequireIdentity, when true (the default), makes every route 401 an
	// unauthenticated caller. Setting it to false is refused by Register
	// unless WithInsecureAllowUnauthenticatedRoutes was also passed, so
	// nobody disables it by accident.
	RequireIdentity bool `json:"require_identity" mapstructure:"require_identity" yaml:"require_identity"`

	// AllowAnonymousChecks opens the three check endpoints
	// (/v1/authz/check, /v1/authz/enforce, /v1/authz/batch-check) to
	// callers with no resolved identity. Every other route, including
	// AuthZEN, still requires one. Off by default.
	AllowAnonymousChecks bool `json:"allow_anonymous_checks" mapstructure:"allow_anonymous_checks" yaml:"allow_anonymous_checks"`

	// AuditLog registers the in-tree plugin/auditlog sink by default,
	// logging one structured line per audit event through the extension
	// logger. On by default; set to false to opt out (e.g. because a
	// different Audit plugin is registered instead).
	AuditLog bool `json:"audit_log" mapstructure:"audit_log" yaml:"audit_log"`
}

// DefaultAuthConfig returns the AuthConfig defaults: identity required,
// anonymous checks off, audit log on.
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		RequireIdentity:      true,
		AllowAnonymousChecks: false,
		AuditLog:             true,
	}
}

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

	// Auth controls authentication/authorization of the management API
	// itself. See AuthConfig.
	Auth AuthConfig `json:"auth" mapstructure:"auth" yaml:"auth"`

	// ─── Engine knobs (mirrors warden.Config; see config.go there) ───

	// CacheTTL is the time-to-live for cached check results. When >0, the
	// engine builds its memory cache from CacheTTL/CacheMaxSize (unless
	// WithEngineOptions already supplied a WithCache).
	CacheTTL time.Duration `json:"cache_ttl" mapstructure:"cache_ttl" yaml:"cache_ttl"`

	// CacheMaxSize bounds the auto-built memory cache's entry count.
	CacheMaxSize int `json:"cache_max_size" mapstructure:"cache_max_size" yaml:"cache_max_size"`

	// MaxGraphVisited caps the number of distinct nodes a ReBAC graph walk
	// may visit before it aborts with ErrGraphBudgetExceeded.
	MaxGraphVisited int `json:"max_graph_visited" mapstructure:"max_graph_visited" yaml:"max_graph_visited"`

	// MaxGraphFanout caps the number of subjects fetched per hop during a
	// ReBAC graph walk.
	MaxGraphFanout int `json:"max_graph_fanout" mapstructure:"max_graph_fanout" yaml:"max_graph_fanout"`

	// EvaluateAllModels, when true, always evaluates RBAC, ReBAC and ABAC
	// even after an earlier model already allowed the request.
	EvaluateAllModels bool `json:"evaluate_all_models" mapstructure:"evaluate_all_models" yaml:"evaluate_all_models"`

	// CheckLogQueueSize bounds the check-log writer's internal channel.
	CheckLogQueueSize int `json:"check_log_queue_size" mapstructure:"check_log_queue_size" yaml:"check_log_queue_size"`

	// CheckLogRetention is how long check log entries are kept before
	// RunMaintenance purges them. 0 disables purging.
	CheckLogRetention time.Duration `json:"check_log_retention" mapstructure:"check_log_retention" yaml:"check_log_retention"`

	// MaintenanceInterval is how often the engine runs RunMaintenance in
	// the background. 0 disables the loop.
	MaintenanceInterval time.Duration `json:"maintenance_interval" mapstructure:"maintenance_interval" yaml:"maintenance_interval"`

	// MaxBatchChecks bounds the number of checks a batch-check or AuthZEN
	// evaluations API call may request in one call.
	MaxBatchChecks int `json:"max_batch_checks" mapstructure:"max_batch_checks" yaml:"max_batch_checks"`

	// RequireTenant, when true (the default), makes Check return
	// ErrTenantRequired whenever the resolved scope has no tenant ID. A
	// nil pointer means "use the engine's default (true)"; only an
	// explicit false disables the requirement.
	RequireTenant *bool `json:"require_tenant,omitempty" mapstructure:"require_tenant" yaml:"require_tenant"`

	// EnableCheckLog enables writing authorization check results to the
	// check log store. A nil pointer means "use the engine's default
	// (true)"; only an explicit false disables it.
	EnableCheckLog *bool `json:"enable_check_log,omitempty" mapstructure:"enable_check_log" yaml:"enable_check_log"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	d := warden.DefaultConfig()
	return Config{
		MaxGraphDepth:       10,
		Auth:                DefaultAuthConfig(),
		CacheMaxSize:        d.CacheMaxSize,
		MaxGraphVisited:     d.MaxGraphVisited,
		MaxGraphFanout:      d.MaxGraphFanout,
		CheckLogQueueSize:   d.CheckLogQueueSize,
		CheckLogRetention:   d.CheckLogRetention,
		MaintenanceInterval: d.MaintenanceInterval,
		MaxBatchChecks:      d.MaxBatchChecks,
	}
}

// Validate checks the extension configuration for internally
// inconsistent values. It delegates the engine-knob checks to
// warden.Config.Validate via toEngineConfig, so the same bounds apply
// whether a value came from YAML, an Option, or a default.
func (c Config) Validate() error {
	if c.MaxGraphDepth < 0 {
		return fmt.Errorf("warden: extension config: max_graph_depth must not be negative, got %d", c.MaxGraphDepth)
	}
	if c.MaxGraphDepth > 64 {
		return fmt.Errorf("warden: extension config: max_graph_depth must not exceed 64, got %d", c.MaxGraphDepth)
	}
	if err := c.toEngineConfig().Validate(); err != nil {
		return fmt.Errorf("warden: extension config: %w", err)
	}
	return nil
}

// toEngineConfig maps the extension's mirrored engine knobs onto a
// warden.Config, for both Validate and the extension's engine wiring.
func (c Config) toEngineConfig() warden.Config {
	return warden.Config{
		MaxGraphDepth:       c.MaxGraphDepth,
		CacheTTL:            c.CacheTTL,
		CacheMaxSize:        c.CacheMaxSize,
		MaxGraphVisited:     c.MaxGraphVisited,
		MaxGraphFanout:      c.MaxGraphFanout,
		EvaluateAllModels:   c.EvaluateAllModels,
		CheckLogQueueSize:   c.CheckLogQueueSize,
		CheckLogRetention:   c.CheckLogRetention,
		MaintenanceInterval: c.MaintenanceInterval,
		MaxBatchChecks:      c.MaxBatchChecks,
		RequireTenant:       c.RequireTenant,
		EnableCheckLog:      c.EnableCheckLog,
	}
}
