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

func maintenanceRunHandler(deps Deps) func(context.Context, struct{}, dashcontract.Principal) (MaintenanceResult, error) {
	return func(ctx context.Context, _ struct{}, p dashcontract.Principal) (MaintenanceResult, error) {
		if err := requireEngine(deps); err != nil {
			return MaintenanceResult{}, err
		}
		if _, err := tenantFrom(p, deps); err != nil {
			return MaintenanceResult{}, err
		}
		// RunMaintenance is engine-wide rather than per-tenant: expired
		// assignments are purged across every tenant and the check log
		// purge uses the configured retention. The tenant check above is
		// an authorization gate on who may trigger it, not a scope.
		rep, err := deps.Engine.RunMaintenance(ctx)
		if err != nil {
			return MaintenanceResult{}, mapWardenError(err)
		}
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

		hasKind, hasID := in.SubjectKind != "", in.SubjectID != ""
		switch {
		case hasKind != hasID:
			return CacheInvalidateResult{}, &dashcontract.Error{
				Code:    dashcontract.CodeBadRequest,
				Message: "subjectKind and subjectId must be given together, or both omitted to flush the tenant",
			}
		case hasKind:
			deps.Engine.InvalidateSubject(ctx, tenantID, warden.SubjectKind(in.SubjectKind), in.SubjectID)
			return CacheInvalidateResult{Scope: "subject"}, nil
		default:
			deps.Engine.InvalidateTenant(ctx, tenantID)
			return CacheInvalidateResult{Scope: "tenant"}, nil
		}
	}
}
