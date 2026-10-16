package warden

import (
	"context"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/warden/internal/telemetry"
)

// MaintenanceReport summarizes one RunMaintenance or RunTenantMaintenance
// pass.
type MaintenanceReport struct {
	AssignmentsPurged int64
	CheckLogsPurged   int64
}

// RunMaintenance purges role assignments that have expired and, when
// Config.CheckLogRetention > 0 (0 or negative is off), check log entries
// older than the retention window, in every tenant. When either purge
// actually removed rows and a Cache is configured, it also does a full
// Cache.Clear: Cache has no "list every tenant" operation, so a targeted
// per-tenant invalidation isn't possible here; a maintenance run is
// infrequent enough that a full flush is cheap relative to serving one
// stale permission.
//
// Each call is a "run maintenance" span, a child of whatever span ctx
// carries. The background loop StartMaintenance runs starts each one as a
// root instead.
func (e *Engine) RunMaintenance(ctx context.Context) (MaintenanceReport, error) {
	return e.runMaintenanceTraced(ctx)
}

// runMaintenanceTraced is RunMaintenance with span start options, so the
// background loop can make each run a root span.
func (e *Engine) runMaintenanceTraced(ctx context.Context, opts ...trace.SpanStartOption) (MaintenanceReport, error) {
	ctx, span := telemetry.StartSpan(ctx, spanRunMaintenance, opts...)
	report, err := e.runMaintenance(ctx)
	endMaintenanceSpan(span, "all", report, err)
	return report, err
}

// runMaintenance is RunMaintenance without its span.
func (e *Engine) runMaintenance(ctx context.Context) (MaintenanceReport, error) {
	now := e.nowFn()
	var report MaintenanceReport

	purged, err := e.store.DeleteExpiredAssignments(ctx, now)
	if err != nil {
		e.maintenanceStoreError(ctx, "delete_expired_assignments")
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
			e.maintenanceStoreError(ctx, "purge_check_logs")
			return report, fmt.Errorf("warden maintenance: purge check logs: %w", err)
		}
		report.CheckLogsPurged = n
		if n > 0 {
			e.metrics.CheckLogsPurged(n)
		}
	}

	if e.cache != nil && (report.AssignmentsPurged > 0 || report.CheckLogsPurged > 0) {
		e.cache.Clear(ctx)
		e.metrics.CacheInvalidated("all")
	}

	return report, nil
}

// RunTenantMaintenance is RunMaintenance for one tenant. It purges that
// tenant's role assignments that have expired and, when
// Config.CheckLogRetention > 0 (0 or negative is off), that tenant's check
// log entries older than the retention window. No other tenant's rows are
// touched. When either purge removed rows and a Cache is configured, it
// invalidates that tenant's cached decisions (Cache.InvalidateTenant), not
// the whole cache.
//
// An empty tenantID returns ErrTenantRequired before anything is deleted:
// the stores read an empty tenant filter as every tenant, so empty is never
// passed through as "all of them". RunMaintenance is the engine-wide pass.
//
// Each call is a "run maintenance" span with scope "tenant", a child of
// whatever span ctx carries. The tenant ID stays off the span.
func (e *Engine) RunTenantMaintenance(ctx context.Context, tenantID string) (MaintenanceReport, error) {
	ctx, span := telemetry.StartSpan(ctx, spanRunMaintenance)
	report, err := e.runTenantMaintenance(ctx, tenantID)
	endMaintenanceSpan(span, "tenant", report, err)
	return report, err
}

// runTenantMaintenance is RunTenantMaintenance without its span.
func (e *Engine) runTenantMaintenance(ctx context.Context, tenantID string) (MaintenanceReport, error) {
	var report MaintenanceReport
	if tenantID == "" {
		return report, ErrTenantRequired
	}
	now := e.nowFn()

	purged, err := e.store.DeleteExpiredAssignmentsForTenant(ctx, tenantID, now)
	if err != nil {
		e.maintenanceStoreError(ctx, "delete_expired_assignments_for_tenant")
		return report, fmt.Errorf("warden maintenance: purge expired assignments for tenant %q: %w", tenantID, err)
	}
	report.AssignmentsPurged = purged
	if purged > 0 {
		e.metrics.AssignmentsPurged(purged)
	}

	if e.config.CheckLogRetention > 0 {
		cutoff := now.Add(-e.config.CheckLogRetention)
		n, err := e.store.PurgeCheckLogsForTenant(ctx, tenantID, cutoff)
		if err != nil {
			e.maintenanceStoreError(ctx, "purge_check_logs_for_tenant")
			return report, fmt.Errorf("warden maintenance: purge check logs for tenant %q: %w", tenantID, err)
		}
		report.CheckLogsPurged = n
		if n > 0 {
			e.metrics.CheckLogsPurged(n)
		}
	}

	if e.cache != nil && (report.AssignmentsPurged > 0 || report.CheckLogsPurged > 0) {
		e.cache.InvalidateTenant(ctx, tenantID)
		e.metrics.CacheInvalidated("tenant")
	}

	return report, nil
}

// maintenanceStoreError counts a failed maintenance purge under op, unless
// ctx had already ended: a run cut short by Stop is not a store failure.
func (e *Engine) maintenanceStoreError(ctx context.Context, op string) {
	if ctx.Err() == nil {
		e.metrics.StoreError(op)
	}
}

// StartMaintenance runs RunMaintenance on Config.MaintenanceInterval until
// ctx is cancelled. A no-op when MaintenanceInterval is 0 or negative, the
// values that switch the loop off. Engine.Start
// calls this automatically; it is also safe to call directly for full
// control over the maintenance context's lifetime. Every run is a root
// "run maintenance" span, even when ctx carries a span (a Forge boot span,
// say), so a run never lands in some long-finished trace.
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
				if _, err := e.runMaintenanceTraced(ctx, trace.WithNewRoot()); err != nil {
					e.logger.Warn("warden: maintenance run failed", log.Error(err))
				}
			}
		}
	}()
}
