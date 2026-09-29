// handlers_maintenance.go: the two operational commands.
//
// These are the only writes warden's config surface has. RunMaintenance
// purges expired assignments and, when CheckLogRetention is set, check log
// entries past it. Cache invalidation is the manual version of what a write
// would do automatically.
package contract

import (
	"context"

	"github.com/xraph/warden"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// MaintenanceResult is the maintenance.run reply.
//
// Both counters are always present, including at zero, because zero is a
// real outcome: the run succeeded and there was nothing to purge. A page
// that could not distinguish that from a failure would have to guess.
type MaintenanceResult struct {
	AssignmentsPurged int64 `json:"assignmentsPurged"`
	CheckLogsPurged   int64 `json:"checkLogsPurged"`
}

// CacheInvalidateInput selects what to flush. Both fields empty flushes the
// whole tenant; both set flushes one subject. One without the other is an
// error rather than a silent widening to the tenant.
type CacheInvalidateInput struct {
	SubjectKind string `json:"subjectKind,omitempty"`
	SubjectID   string `json:"subjectId,omitempty"`
}

// CacheInvalidateResult reports which scope was flushed, so the page can say
// what it did rather than "done".
type CacheInvalidateResult struct {
	Scope string `json:"scope"` // "tenant" or "subject"
}

// maintenanceRunHandler runs one maintenance pass.
//
// maintenance.run is engine-wide, not tenant-scoped. RunMaintenance purges
// expired assignments across every tenant and purges check log entries
// past the configured retention across every tenant. The caller's tenant
// decides nothing about what is removed; it only names the scope the
// authorization decision and the audit event are recorded under. That is
// why the intent sits behind its own warden:maintenance:manage permission
// rather than a role or assignment grant, and why every run is audited with
// the resulting counts.
func maintenanceRunHandler(deps Deps) func(context.Context, struct{}, dashcontract.Principal) (MaintenanceResult, error) {
	return func(ctx context.Context, _ struct{}, p dashcontract.Principal) (MaintenanceResult, error) {
		if err := requireEngine(deps); err != nil {
			return MaintenanceResult{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return MaintenanceResult{}, err
		}
		ctx = withActor(ctx, p)
		rep, err := deps.Engine.RunMaintenance(ctx)
		if err != nil {
			return MaintenanceResult{}, mapWardenError(err)
		}
		emitAudit(ctx, deps, p, "maintenance.run", tenantID, "", rep, nil)
		return MaintenanceResult{
			AssignmentsPurged: rep.AssignmentsPurged,
			CheckLogsPurged:   rep.CheckLogsPurged,
		}, nil
	}
}

func cacheInvalidateHandler(deps Deps) func(context.Context, CacheInvalidateInput, dashcontract.Principal) (CacheInvalidateResult, error) {
	return func(ctx context.Context, in CacheInvalidateInput, p dashcontract.Principal) (CacheInvalidateResult, error) {
		if err := requireEngine(deps); err != nil {
			return CacheInvalidateResult{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return CacheInvalidateResult{}, err
		}
		ctx = withActor(ctx, p)

		hasKind, hasID := in.SubjectKind != "", in.SubjectID != ""
		switch {
		case hasKind != hasID:
			return CacheInvalidateResult{}, &dashcontract.Error{
				Code:    dashcontract.CodeBadRequest,
				Message: "subjectKind and subjectId must be given together, or both omitted to flush the tenant",
			}
		case hasKind:
			deps.Engine.InvalidateSubject(ctx, tenantID, warden.SubjectKind(in.SubjectKind), in.SubjectID)
			emitAudit(ctx, deps, p, "maintenance.cache_invalidated", tenantID, in.SubjectID, map[string]string{
				"scope": "subject", "subject_kind": in.SubjectKind, "subject_id": in.SubjectID,
			}, nil)
			return CacheInvalidateResult{Scope: "subject"}, nil
		default:
			deps.Engine.InvalidateTenant(ctx, tenantID)
			emitAudit(ctx, deps, p, "maintenance.cache_invalidated", tenantID, "", map[string]string{
				"scope": "tenant",
			}, nil)
			return CacheInvalidateResult{Scope: "tenant"}, nil
		}
	}
}
