// handlers_overview.go: the entity counters and the recent-checks list.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// OverviewStats is the overview.stats response: one counter per entity kind
// in a single payload, so the six stat tiles cost one request.
type OverviewStats struct {
	Roles         int64 `json:"roles"`
	Permissions   int64 `json:"permissions"`
	Assignments   int64 `json:"assignments"`
	Relations     int64 `json:"relations"`
	Policies      int64 `json:"policies"`
	ResourceTypes int64 `json:"resourceTypes"`
}

// CheckLogSummary is one row of the recent-checks list and of the check log
// page. Cached and Error are carried because they are this page's scan
// signal: allow versus deny volume depends on the deployment's posture, so
// neither can be the thing colour keys off.
type CheckLogSummary struct {
	ID            string `json:"id"`
	NamespacePath string `json:"namespacePath"`
	SubjectKind   string `json:"subjectKind"`
	SubjectID     string `json:"subjectId"`
	Action        string `json:"action"`
	ResourceType  string `json:"resourceType"`
	ResourceID    string `json:"resourceId"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	EvalTimeNs    int64  `json:"evalTimeNs"`
	Cached        bool   `json:"cached"`
	Error         string `json:"error,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

// RecentChecksInput caps the list. Zero or negative means the default of 10.
type RecentChecksInput struct {
	Limit int `json:"limit,omitempty"`
}

// RecentChecksResponse is the overview.recentChecks reply.
type RecentChecksResponse struct {
	Checks []CheckLogSummary `json:"checks"`
}

func overviewStatsHandler(deps Deps) func(context.Context, struct{}, dashcontract.Principal) (OverviewStats, error) {
	return func(ctx context.Context, _ struct{}, p dashcontract.Principal) (OverviewStats, error) {
		if err := requireEngine(deps); err != nil {
			return OverviewStats{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return OverviewStats{}, err
		}
		s := deps.Engine.Store()

		var out OverviewStats
		// Each count is a separate store call because each ListFilter is a
		// different type. A failure in any one is reported rather than
		// silently rendered as zero: a zero an operator cannot distinguish
		// from an error is worse than an error.
		if out.Roles, err = s.CountRoles(ctx, &role.ListFilter{TenantID: tenantID}); err != nil {
			return OverviewStats{}, mapWardenError(err)
		}
		if out.Permissions, err = s.CountPermissions(ctx, &permission.ListFilter{TenantID: tenantID}); err != nil {
			return OverviewStats{}, mapWardenError(err)
		}
		if out.Assignments, err = s.CountAssignments(ctx, &assignment.ListFilter{TenantID: tenantID}); err != nil {
			return OverviewStats{}, mapWardenError(err)
		}
		if out.Relations, err = s.CountRelations(ctx, &relation.ListFilter{TenantID: tenantID}); err != nil {
			return OverviewStats{}, mapWardenError(err)
		}
		if out.Policies, err = s.CountPolicies(ctx, &policy.ListFilter{TenantID: tenantID}); err != nil {
			return OverviewStats{}, mapWardenError(err)
		}
		if out.ResourceTypes, err = s.CountResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID}); err != nil {
			return OverviewStats{}, mapWardenError(err)
		}
		return out, nil
	}
}

func overviewRecentChecksHandler(deps Deps) func(context.Context, RecentChecksInput, dashcontract.Principal) (RecentChecksResponse, error) {
	return func(ctx context.Context, in RecentChecksInput, p dashcontract.Principal) (RecentChecksResponse, error) {
		if err := requireEngine(deps); err != nil {
			return RecentChecksResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return RecentChecksResponse{}, err
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 10
		}
		entries, err := deps.Engine.Store().ListCheckLogs(ctx, &checklog.QueryFilter{
			TenantID: tenantID,
			Limit:    limit,
		})
		if err != nil {
			return RecentChecksResponse{}, mapWardenError(err)
		}
		out := RecentChecksResponse{Checks: make([]CheckLogSummary, 0, len(entries))}
		for _, e := range entries {
			out.Checks = append(out.Checks, projectCheckLog(e))
		}
		return out, nil
	}
}

// projectCheckLog is shared by overview.recentChecks and checkLogs.list, so
// the two never disagree about what a row looks like.
func projectCheckLog(e *checklog.Entry) CheckLogSummary {
	return CheckLogSummary{
		ID:            e.ID.String(),
		NamespacePath: e.NamespacePath,
		SubjectKind:   e.SubjectKind,
		SubjectID:     e.SubjectID,
		Action:        e.Action,
		ResourceType:  e.ResourceType,
		ResourceID:    e.ResourceID,
		Decision:      e.Decision,
		Reason:        e.Reason,
		EvalTimeNs:    e.EvalTimeNs,
		Cached:        e.Cached,
		Error:         e.Error,
		CreatedAt:     e.CreatedAt.UTC().Format(time.RFC3339),
	}
}
