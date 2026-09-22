package warden

import (
	"fmt"
	"time"
)

// Config holds configuration for the Warden engine.
type Config struct {
	// MaxGraphDepth is the maximum depth for ReBAC graph traversal.
	// Defaults to 10.
	MaxGraphDepth int `json:"max_graph_depth,omitempty"`

	// CacheTTL is the time-to-live for cached check results. When >0 and no
	// Cache was supplied via WithCache, the engine builds a memory cache
	// (NewMemoryCache) from CacheTTL and CacheMaxSize. Zero means no
	// caching unless a Cache was set explicitly.
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`

	// CacheMaxSize bounds the number of entries the auto-built memory cache
	// holds per shard set. Defaults to 10000. Ignored when a Cache is
	// supplied explicitly via WithCache.
	CacheMaxSize int `json:"cache_max_size,omitempty"`

	// EnableRBAC enables role-based access control evaluation.
	// Defaults to true.
	EnableRBAC *bool `json:"enable_rbac,omitempty"`

	// EnableABAC enables attribute-based access control evaluation.
	// Defaults to true.
	EnableABAC *bool `json:"enable_abac,omitempty"`

	// EnableReBAC enables relationship-based access control evaluation.
	// Defaults to true.
	EnableReBAC *bool `json:"enable_rebac,omitempty"`

	// EnableCheckLog enables writing authorization check results to the
	// check log store. Defaults to true.
	EnableCheckLog *bool `json:"enable_check_log,omitempty"`

	// RequireTenant, when true (the default), makes Check return
	// ErrTenantRequired whenever the resolved scope has no tenant ID.
	// Set to false for single-tenant / standalone deployments that never
	// call WithTenant.
	RequireTenant *bool `json:"require_tenant,omitempty"`

	// MaxGraphVisited caps the number of distinct nodes a ReBAC graph walk
	// may visit before it aborts with ErrGraphBudgetExceeded. Defaults to
	// 5000.
	MaxGraphVisited int `json:"max_graph_visited,omitempty"`

	// MaxGraphFanout caps the number of subjects fetched per hop during a
	// ReBAC graph walk (passed through to ListRelationSubjects). Defaults
	// to 1000.
	MaxGraphFanout int `json:"max_graph_fanout,omitempty"`

	// EvaluateAllModels, when true, always evaluates RBAC, ReBAC and ABAC
	// even after an earlier model already allowed the request. Defaults to
	// false: ReBAC is skipped once RBAC already allowed.
	EvaluateAllModels bool `json:"evaluate_all_models,omitempty"`

	// CheckLogQueueSize bounds the check-log writer's internal channel.
	// Defaults to 4096. When full, new entries are dropped rather than
	// blocking Check.
	CheckLogQueueSize int `json:"check_log_queue_size,omitempty"`

	// CheckLogRetention is how long check log entries are kept before
	// RunMaintenance purges them. Defaults to 90 days; 0 disables purging.
	CheckLogRetention time.Duration `json:"check_log_retention,omitempty"`

	// MaintenanceInterval is how often Engine.Start runs RunMaintenance in
	// the background. Defaults to 1 hour; 0 disables the loop.
	MaintenanceInterval time.Duration `json:"maintenance_interval,omitempty"`

	// MaxBatchChecks bounds the number of checks a batch-check API call may
	// request in one call. Defaults to 100.
	MaxBatchChecks int `json:"max_batch_checks,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	t := true
	return Config{
		MaxGraphDepth:       10,
		EnableRBAC:          &t,
		EnableABAC:          &t,
		EnableReBAC:         &t,
		EnableCheckLog:      &t,
		RequireTenant:       &t,
		CacheMaxSize:        10000,
		MaxGraphVisited:     5000,
		MaxGraphFanout:      1000,
		EvaluateAllModels:   false,
		CheckLogQueueSize:   4096,
		CheckLogRetention:   90 * 24 * time.Hour,
		MaintenanceInterval: time.Hour,
		MaxBatchChecks:      100,
	}
}

func (c Config) rbacEnabled() bool     { return c.EnableRBAC == nil || *c.EnableRBAC }
func (c Config) abacEnabled() bool     { return c.EnableABAC == nil || *c.EnableABAC }
func (c Config) rebacEnabled() bool    { return c.EnableReBAC == nil || *c.EnableReBAC }
func (c Config) checkLogEnabled() bool { return c.EnableCheckLog == nil || *c.EnableCheckLog }
func (c Config) requireTenant() bool   { return c.RequireTenant == nil || *c.RequireTenant }

// Validate checks the configuration for internally inconsistent or unsafe
// values: negative durations/counts, a cache TTL over 24h, and a graph
// depth over 64.
func (c Config) Validate() error {
	if c.MaxGraphDepth < 0 {
		return fmt.Errorf("warden: config: MaxGraphDepth must not be negative, got %d", c.MaxGraphDepth)
	}
	if c.MaxGraphDepth > 64 {
		return fmt.Errorf("warden: config: MaxGraphDepth must not exceed 64, got %d", c.MaxGraphDepth)
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("warden: config: CacheTTL must not be negative, got %s", c.CacheTTL)
	}
	if c.CacheTTL > 24*time.Hour {
		return fmt.Errorf("warden: config: CacheTTL must not exceed 24h, got %s", c.CacheTTL)
	}
	if c.CacheMaxSize < 0 {
		return fmt.Errorf("warden: config: CacheMaxSize must not be negative, got %d", c.CacheMaxSize)
	}
	if c.MaxGraphVisited < 0 {
		return fmt.Errorf("warden: config: MaxGraphVisited must not be negative, got %d", c.MaxGraphVisited)
	}
	if c.MaxGraphFanout < 0 {
		return fmt.Errorf("warden: config: MaxGraphFanout must not be negative, got %d", c.MaxGraphFanout)
	}
	if c.CheckLogQueueSize < 0 {
		return fmt.Errorf("warden: config: CheckLogQueueSize must not be negative, got %d", c.CheckLogQueueSize)
	}
	if c.CheckLogRetention < 0 {
		return fmt.Errorf("warden: config: CheckLogRetention must not be negative, got %s", c.CheckLogRetention)
	}
	if c.MaintenanceInterval < 0 {
		return fmt.Errorf("warden: config: MaintenanceInterval must not be negative, got %s", c.MaintenanceInterval)
	}
	if c.MaxBatchChecks < 0 {
		return fmt.Errorf("warden: config: MaxBatchChecks must not be negative, got %d", c.MaxBatchChecks)
	}
	return nil
}
