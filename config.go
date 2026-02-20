package warden

import "time"

// Config holds configuration for the Warden engine.
type Config struct {
	// MaxGraphDepth is the maximum depth for ReBAC graph traversal.
	// Defaults to 10.
	MaxGraphDepth int `json:"max_graph_depth,omitempty"`

	// CacheTTL is the time-to-live for cached check results.
	// Zero means no caching.
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`

	// EnableRBAC enables role-based access control evaluation.
	// Defaults to true.
	EnableRBAC *bool `json:"enable_rbac,omitempty"`

	// EnableABAC enables attribute-based access control evaluation.
	// Defaults to true.
	EnableABAC *bool `json:"enable_abac,omitempty"`

	// EnableReBAC enables relationship-based access control evaluation.
	// Defaults to true.
	EnableReBAC *bool `json:"enable_rebac,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	t := true
	return Config{
		MaxGraphDepth: 10,
		EnableRBAC:    &t,
		EnableABAC:    &t,
		EnableReBAC:   &t,
	}
}

func (c Config) rbacEnabled() bool  { return c.EnableRBAC == nil || *c.EnableRBAC }
func (c Config) abacEnabled() bool  { return c.EnableABAC == nil || *c.EnableABAC }
func (c Config) rebacEnabled() bool { return c.EnableReBAC == nil || *c.EnableReBAC }
