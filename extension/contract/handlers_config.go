// handlers_config.go: the read-only view of the engine's configuration.
//
// Warden's Config comes from Forge config, not from a store, so there is no
// write path and no settings intent. The templ dashboard's settings panel had
// no inputs either: it showed some of these values as text and badges.
package contract

import (
	"context"
	"slices"
	"time"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// ConfigDetail is the config.detail response.
//
// Durations are flattened to whole units because the wire carries JSON and a
// Go duration serialises as a nanosecond integer nobody can read. The page
// formats from these.
type ConfigDetail struct {
	MaxGraphDepth     int  `json:"maxGraphDepth"`
	MaxGraphVisited   int  `json:"maxGraphVisited"`
	MaxGraphFanout    int  `json:"maxGraphFanout"`
	MaxBatchChecks    int  `json:"maxBatchChecks"`
	CacheTTLSeconds   int  `json:"cacheTtlSeconds"`
	CacheMaxSize      int  `json:"cacheMaxSize"`
	RBACEnabled       bool `json:"rbacEnabled"`
	ABACEnabled       bool `json:"abacEnabled"`
	ReBACEnabled      bool `json:"rebacEnabled"`
	CheckLogEnabled   bool `json:"checkLogEnabled"`
	RequireTenant     bool `json:"requireTenant"`
	EvaluateAllModels bool `json:"evaluateAllModels"`
	CheckLogQueueSize int  `json:"checkLogQueueSize"`
	// CheckLogRetentionSeconds and MaintenanceIntervalSeconds carry the
	// durations in whole seconds, rounded up, so a positive duration never
	// reads as 0, and 0 means off: the engine purges no check log entries
	// (or runs no maintenance loop). The engine reads a 0 or negative
	// duration as off, and both are sent as 0, so the wire never carries a
	// negative number. CheckLogRetentionHours and MaintenanceIntervalMin
	// stay for clients older than the seconds fields. They are rounded down
	// and also 0 when off, so there a retention under an hour reads 0, the
	// same as no retention at all.
	CheckLogRetentionSeconds   int64 `json:"checkLogRetentionSeconds"`
	MaintenanceIntervalSeconds int64 `json:"maintenanceIntervalSeconds"`
	CheckLogRetentionHours     int64 `json:"checkLogRetentionHours"`
	MaintenanceIntervalMin     int64 `json:"maintenanceIntervalMinutes"`
	// Plugins is the name of every plugin in the engine's registry when the
	// request was served, sorted. It can include plugins warden registers on
	// its own, such as the cache invalidators and the audit log sink, beside
	// any a caller passed in. Never nil: an engine with no registry sends [].
	Plugins []string `json:"plugins"`
}

// pluginNames lists the registry's plugin names, sorted. The registry is not
// frozen when the engine starts (anything holding the engine can call
// Plugins().Register later), so this is read on every request.
func pluginNames(deps Deps) []string {
	names := []string{}
	reg := deps.Engine.Plugins()
	if reg == nil {
		return names
	}
	for _, p := range reg.Plugins() {
		names = append(names, p.Name())
	}
	slices.Sort(names)
	return names
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
			MaxGraphDepth:              c.MaxGraphDepth,
			MaxGraphVisited:            c.MaxGraphVisited,
			MaxGraphFanout:             c.MaxGraphFanout,
			MaxBatchChecks:             c.MaxBatchChecks,
			CacheTTLSeconds:            int(c.CacheTTL.Seconds()),
			CacheMaxSize:               c.CacheMaxSize,
			RBACEnabled:                enabled(c.EnableRBAC),
			ABACEnabled:                enabled(c.EnableABAC),
			ReBACEnabled:               enabled(c.EnableReBAC),
			CheckLogEnabled:            enabled(c.EnableCheckLog),
			RequireTenant:              enabled(c.RequireTenant),
			EvaluateAllModels:          c.EvaluateAllModels,
			CheckLogQueueSize:          c.CheckLogQueueSize,
			CheckLogRetentionSeconds:   ceilSeconds(c.CheckLogRetention),
			MaintenanceIntervalSeconds: ceilSeconds(c.MaintenanceInterval),
			CheckLogRetentionHours:     floorUnits(c.CheckLogRetention, time.Hour),
			MaintenanceIntervalMin:     floorUnits(c.MaintenanceInterval, time.Minute),
			Plugins:                    pluginNames(deps),
		}, nil
	}
}

// ceilSeconds is d in whole seconds, rounded up, so a positive duration
// never reads as 0 (which the page shows as "off"). A 0 or negative d is
// off and reads 0.
func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// floorUnits is d in whole units, rounded down, for the fields older
// clients read. A 0 or negative d is off and reads 0, never a negative
// number.
func floorUnits(d, unit time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(d / unit)
}
