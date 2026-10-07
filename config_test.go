package warden

import (
	"testing"
	"time"
)

func TestConfigValidate_DefaultsOK(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config should validate, got %v", err)
	}
}

func TestConfigValidate_RejectsNegatives(t *testing.T) {
	base := DefaultConfig()

	tests := []struct {
		name   string
		mutate func(c Config) Config
	}{
		{"MaxGraphDepth", func(c Config) Config { c.MaxGraphDepth = -1; return c }},
		{"CacheTTL", func(c Config) Config { c.CacheTTL = -time.Second; return c }},
		{"CacheMaxSize", func(c Config) Config { c.CacheMaxSize = -1; return c }},
		{"MaxGraphVisited", func(c Config) Config { c.MaxGraphVisited = -1; return c }},
		{"MaxGraphFanout", func(c Config) Config { c.MaxGraphFanout = -1; return c }},
		{"CheckLogQueueSize", func(c Config) Config { c.CheckLogQueueSize = -1; return c }},
		{"MaxBatchChecks", func(c Config) Config { c.MaxBatchChecks = -1; return c }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mutate(base).Validate(); err == nil {
				t.Fatalf("expected error for negative %s", tc.name)
			}
		})
	}
}

// A negative CheckLogRetention or MaintenanceInterval is how a caller
// switches purging or the loop off through the Forge extension, which reads
// 0 as "use the default". Validate must let it through.
func TestConfigValidate_AcceptsNegativeRetentionAndInterval(t *testing.T) {
	c := DefaultConfig()
	c.CheckLogRetention = -time.Hour
	c.MaintenanceInterval = -time.Nanosecond
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a negative retention and interval to validate, got %v", err)
	}
}

func TestConfigValidate_RejectsCacheTTLOver24h(t *testing.T) {
	c := DefaultConfig()
	c.CacheTTL = 25 * time.Hour
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for CacheTTL over 24h")
	}
}

func TestConfigValidate_AllowsCacheTTLExactly24h(t *testing.T) {
	c := DefaultConfig()
	c.CacheTTL = 24 * time.Hour
	if err := c.Validate(); err != nil {
		t.Fatalf("expected 24h CacheTTL to validate, got %v", err)
	}
}

func TestConfigValidate_RejectsMaxGraphDepthOver64(t *testing.T) {
	c := DefaultConfig()
	c.MaxGraphDepth = 65
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MaxGraphDepth over 64")
	}
}

func TestConfigValidate_AllowsMaxGraphDepthExactly64(t *testing.T) {
	c := DefaultConfig()
	c.MaxGraphDepth = 64
	if err := c.Validate(); err != nil {
		t.Fatalf("expected MaxGraphDepth=64 to validate, got %v", err)
	}
}

func TestConfig_RequireTenantDefaultsTrue(t *testing.T) {
	c := DefaultConfig()
	if !c.requireTenant() {
		t.Fatal("expected RequireTenant to default true")
	}
}
