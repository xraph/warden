// handlers_checklogs.go: the check log list and one check's detail.
//
// There is no purge. PurgeCheckLogs takes no tenant id, so a dashboard
// purge would let one tenant delete every tenant's audit trail. Retention
// runs through maintenance.run.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// CheckLogsListInput is the checkLogs.list request. Every filter is
// optional and they combine with AND.
type CheckLogsListInput struct {
	PageRequest
	// NamespacePath is a pointer because the root namespace is the empty
	// string: nil means every namespace, "" means the root only.
	NamespacePath *string `json:"namespacePath,omitempty"`
	SubjectKind   string  `json:"subjectKind,omitempty"`
	SubjectID     string  `json:"subjectId,omitempty"`
	Action        string  `json:"action,omitempty"`
	ResourceType  string  `json:"resourceType,omitempty"`
	ResourceID    string  `json:"resourceId,omitempty"`
	Decision      string  `json:"decision,omitempty"`
	Cached        *bool   `json:"cached,omitempty"`
	// After and Before are RFC 3339 instants, both inclusive. Empty means
	// unbounded.
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`
}

// CheckLogLossView is the engine's count of decided checks that left no
// row. It is per server process and covers every tenant that process
// serves, because the writer's queue is shared.
type CheckLogLossView struct {
	QueueFull   uint64 `json:"queueFull"`
	WriteFailed uint64 `json:"writeFailed"`
	Since       string `json:"since"`
}

// CheckLogsListResponse is the checkLogs.list reply.
type CheckLogsListResponse struct {
	PageMeta
	Items []CheckLogSummary `json:"items"`
	// NotRecorded is absent when check logging is off.
	NotRecorded *CheckLogLossView `json:"notRecorded,omitempty"`
}

// CheckLogDetailInput is the checkLogs.detail request.
type CheckLogDetailInput struct {
	ID string `json:"id"`
}

// CheckLogMatch is one rule that contributed to a decision.
type CheckLogMatch struct {
	Source string `json:"source"`
	RuleID string `json:"ruleId,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// CheckLogDetail is the checkLogs.detail reply: the summary plus what an
// auditor needs to reconstruct the decision without replaying the check.
type CheckLogDetail struct {
	CheckLogSummary
	AppID       string          `json:"appId,omitempty"`
	MatchedBy   []CheckLogMatch `json:"matchedBy"`
	Obligations []string        `json:"obligations"`
	RequestIP   string          `json:"requestIp,omitempty"`
	RequestID   string          `json:"requestId,omitempty"`
	TraceID     string          `json:"traceId,omitempty"`
}

// knownDecisions is every value buildCheckLogEntry can write. A decision
// filter outside it can only match nothing, and an empty page that reads
// as "nothing happened" is worse than a refusal.
var knownDecisions = map[string]bool{
	string(warden.DecisionAllow):         true,
	string(warden.DecisionDeny):          true,
	string(warden.DecisionDenyExplicit):  true,
	string(warden.DecisionDenyDefault):   true,
	string(warden.DecisionDenyNoRoles):   true,
	string(warden.DecisionDenyNoPerms):   true,
	string(warden.DecisionDenyCondition): true,
	string(warden.DecisionDenyRelation):  true,
	"error":                              true,
}

func parseInstant(field, raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, badRequest(field + " is not an RFC 3339 time: " + raw)
	}
	return &t, nil
}

func checkLogsListHandler(deps Deps) func(context.Context, CheckLogsListInput, dashcontract.Principal) (CheckLogsListResponse, error) {
	return func(ctx context.Context, in CheckLogsListInput, p dashcontract.Principal) (CheckLogsListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return CheckLogsListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return CheckLogsListResponse{}, err
		}
		if in.Decision != "" && !knownDecisions[in.Decision] {
			return CheckLogsListResponse{}, badRequest("decision is not one warden records: " + in.Decision)
		}
		after, err := parseInstant("after", in.After)
		if err != nil {
			return CheckLogsListResponse{}, err
		}
		before, err := parseInstant("before", in.Before)
		if err != nil {
			return CheckLogsListResponse{}, err
		}
		if after != nil && before != nil && after.After(*before) {
			return CheckLogsListResponse{}, badRequest("after is later than before")
		}

		limit, offset := in.Clamp()
		filter := checklog.QueryFilter{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			SubjectKind:   in.SubjectKind,
			SubjectID:     in.SubjectID,
			Action:        in.Action,
			ResourceType:  in.ResourceType,
			ResourceID:    in.ResourceID,
			Decision:      in.Decision,
			Cached:        in.Cached,
			After:         after,
			Before:        before,
		}

		s := deps.Engine.Store()
		total, err := s.CountCheckLogs(ctx, &filter)
		if err != nil {
			return CheckLogsListResponse{}, mapWardenError(err)
		}
		page := filter
		page.Limit, page.Offset = limit, offset
		entries, err := s.ListCheckLogs(ctx, &page)
		if err != nil {
			return CheckLogsListResponse{}, mapWardenError(err)
		}

		out := CheckLogsListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]CheckLogSummary, 0, len(entries)),
		}
		for _, e := range entries {
			out.Items = append(out.Items, projectCheckLog(e))
		}
		if loss, ok := deps.Engine.CheckLogLoss(); ok {
			out.NotRecorded = &CheckLogLossView{
				QueueFull:   loss.QueueFull,
				WriteFailed: loss.WriteFailed,
				Since:       loss.Since.UTC().Format(time.RFC3339),
			}
		}
		return out, nil
	}
}

func checkLogsDetailHandler(deps Deps) func(context.Context, CheckLogDetailInput, dashcontract.Principal) (CheckLogDetail, error) {
	return func(ctx context.Context, in CheckLogDetailInput, p dashcontract.Principal) (CheckLogDetail, error) {
		if err := requireEngine(deps); err != nil {
			return CheckLogDetail{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return CheckLogDetail{}, err
		}
		logID, err := id.ParseCheckLogID(in.ID)
		if err != nil {
			return CheckLogDetail{}, badRequest("not a check log id: " + in.ID)
		}
		e, err := deps.Engine.Store().GetCheckLog(ctx, tenantID, logID)
		if err != nil {
			return CheckLogDetail{}, mapWardenError(err)
		}

		out := CheckLogDetail{
			CheckLogSummary: projectCheckLog(e),
			AppID:           e.AppID,
			MatchedBy:       make([]CheckLogMatch, 0, len(e.MatchedBy)),
			Obligations:     make([]string, 0, len(e.Obligations)),
			RequestIP:       e.RequestIP,
			RequestID:       e.RequestID,
			TraceID:         e.TraceID,
		}
		for _, m := range e.MatchedBy {
			out.MatchedBy = append(out.MatchedBy, CheckLogMatch{Source: m.Source, RuleID: m.RuleID, Detail: m.Detail})
		}
		out.Obligations = append(out.Obligations, e.Obligations...)
		return out, nil
	}
}
