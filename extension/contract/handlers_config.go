// handlers_config.go: the read-only view of the engine's configuration.
//
// Warden's Config comes from Forge config, not from a store, so there is no
// write path and no settings intent. The templ dashboard rendered these same
// fields with every input marked Disabled.
package contract

import (
	"context"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// ConfigDetail is the config.detail response.
//
// Durations are flattened to whole units because the wire carries JSON and a
// Go duration serialises as a nanosecond integer nobody can read. The page
// formats from these.
type ConfigDetail struct {
	MaxGraphDepth          int   `json:"maxGraphDepth"`
	MaxGraphVisited        int   `json:"maxGraphVisited"`
	MaxGraphFanout         int   `json:"maxGraphFanout"`
	MaxBatchChecks         int   `json:"maxBatchChecks"`
	CacheTTLSeconds        int   `json:"cacheTtlSeconds"`
	CacheMaxSize           int   `json:"cacheMaxSize"`
	RBACEnabled            bool  `json:"rbacEnabled"`
	ABACEnabled            bool  `json:"abacEnabled"`
	ReBACEnabled           bool  `json:"rebacEnabled"`
	CheckLogEnabled        bool  `json:"checkLogEnabled"`
	RequireTenant          bool  `json:"requireTenant"`
	EvaluateAllModels      bool  `json:"evaluateAllModels"`
	CheckLogQueueSize      int   `json:"checkLogQueueSize"`
	CheckLogRetentionHours int64 `json:"checkLogRetentionHours"`
	MaintenanceIntervalMin int64 `json:"maintenanceIntervalMinutes"`
}

// enabled reads one of Config's tri-state flags. A nil pointer means the
// default, and every Enable* default is true.
func enabled(flag *bool) bool { return flag == nil || *flag }

func configDetailHandler(deps Deps) func(context.Context, struct{}, dashcontract.Principal) (ConfigDetail, error) {
	return func(_ context.Context, _ struct{}, _ dashcontract.Principal) (ConfigDetail, error) {
		if err := requireEngine(deps); err != nil {
			return ConfigDetail{}, err
		}
		c := deps.Engine.Config()
		return ConfigDetail{
			MaxGraphDepth:          c.MaxGraphDepth,
			MaxGraphVisited:        c.MaxGraphVisited,
			MaxGraphFanout:         c.MaxGraphFanout,
			MaxBatchChecks:         c.MaxBatchChecks,
			CacheTTLSeconds:        int(c.CacheTTL.Seconds()),
			CacheMaxSize:           c.CacheMaxSize,
			RBACEnabled:            enabled(c.EnableRBAC),
			ABACEnabled:            enabled(c.EnableABAC),
			ReBACEnabled:           enabled(c.EnableReBAC),
			CheckLogEnabled:        enabled(c.EnableCheckLog),
			RequireTenant:          enabled(c.RequireTenant),
			EvaluateAllModels:      c.EvaluateAllModels,
			CheckLogQueueSize:      c.CheckLogQueueSize,
			CheckLogRetentionHours: int64(c.CheckLogRetention.Hours()),
			MaintenanceIntervalMin: int64(c.MaintenanceInterval.Minutes()),
		}, nil
	}
}
