package warden

import (
	"context"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"
)

// MaintenanceReport summarizes one RunMaintenance pass.
type MaintenanceReport struct {
	AssignmentsPurged int64
	CheckLogsPurged   int64
}

// RunMaintenance purges role assignments that have expired and, when
// Config.CheckLogRetention > 0, check log entries older than the retention
// window. When either purge actually removed rows and a Cache is
// configured, it also does a full Cache.Clear: Cache has no "list every
// tenant" operation, so a targeted per-tenant invalidation isn't possible
// here; a maintenance run is infrequent enough that a full flush is cheap
// relative to serving one stale permission.
func (e *Engine) RunMaintenance(ctx context.Context) (MaintenanceReport, error) {
	now := e.nowFn()
	var report MaintenanceReport

	purged, err := e.store.DeleteExpiredAssignments(ctx, now)
	if err != nil {
		return report, fmt.Errorf("warden maintenance: purge expired assignments: %w", err)
	}
	report.AssignmentsPurged = purged
	if purged > 0 {
		e.metrics.AssignmentsPurged(purged)
	}

	if e.config.CheckLogRetention > 0 {
		cutoff := now.Add(-e.config.CheckLogRetention)
		n, err := e.store.PurgeCheckLogs(ctx, cutoff)
		if err != nil {
			return report, fmt.Errorf("warden maintenance: purge check logs: %w", err)
		}
		report.CheckLogsPurged = n
		if n > 0 {
			e.metrics.CheckLogsPurged(n)
		}
	}

	if e.cache != nil && (report.AssignmentsPurged > 0 || report.CheckLogsPurged > 0) {
		e.cache.Clear(ctx)
		e.metrics.CacheInvalidated("tenant")
	}

	return report, nil
}

// StartMaintenance runs RunMaintenance on Config.MaintenanceInterval until
// ctx is cancelled. A no-op when MaintenanceInterval <= 0. Engine.Start
// calls this automatically; it is also safe to call directly for full
// control over the maintenance context's lifetime.
func (e *Engine) StartMaintenance(ctx context.Context) {
	if e.config.MaintenanceInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(e.config.MaintenanceInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := e.RunMaintenance(ctx); err != nil {
					e.logger.Warn("warden: maintenance run failed", log.Error(err))
				}
			}
		}
	}()
}
