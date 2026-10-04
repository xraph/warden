// handlers_playground.go: the policy playground's explain intent.
//
// playground.batchCheck runs several checks as dry runs at one namespace and
// reports each outcome.
//
// playground.explain runs one authorization check as a dry run and reports
// what each model did. The check it builds writes no check log row, fires no
// hooks and reads no cache, so it is a query: a viewer who may run checks may
// run it. Authorizing the call is a dry run too, as for every query.
package contract

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/warden"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// PlaygroundExplainInput is the playground.explain request.
//
// There is no tenant field, on purpose. The tenant is the caller's, resolved
// by tenantFrom, so a request can never ask about another tenant's data.
type PlaygroundExplainInput struct {
	SubjectKind  string `json:"subjectKind"`
	SubjectID    string `json:"subjectId"`
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId,omitempty"`
	// NamespacePath is where the check runs. "" is the tenant root. Always
	// explicit: a playground check is at a namespace, never "any".
	NamespacePath      string         `json:"namespacePath"`
	Context            map[string]any `json:"context,omitempty"`
	SubjectAttributes  map[string]any `json:"subjectAttributes,omitempty"`
	ResourceAttributes map[string]any `json:"resourceAttributes,omitempty"`
}

// PlaygroundLane is one authorization model's part in an explained check.
type PlaygroundLane struct {
	// Model is "rbac", "rebac" or "abac".
	Model string `json:"model"`
	// State is one of warden.LaneState's values.
	State           string          `json:"state"`
	Decision        string          `json:"decision,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	MatchedBy       []CheckLogMatch `json:"matchedBy"`
	WalkTruncated   bool            `json:"walkTruncated,omitempty"`
	ExpressionError string          `json:"expressionError,omitempty"`
	Error           string          `json:"error,omitempty"`
}

// PlaygroundExplainResponse is the playground.explain reply.
type PlaygroundExplainResponse struct {
	// Decision is "error" when a model failed, with Error set; otherwise
	// the merged decision.
	Decision    string          `json:"decision"`
	Allowed     bool            `json:"allowed"`
	Reason      string          `json:"reason,omitempty"`
	Error       string          `json:"error,omitempty"`
	MatchedBy   []CheckLogMatch `json:"matchedBy"`
	Obligations []string        `json:"obligations"`
	EvalTimeNs  int64           `json:"evalTimeNs"`
	// Lanes is always three, in pipeline order: rbac, rebac, abac.
	Lanes []PlaygroundLane `json:"lanes"`
}

func playgroundExplainHandler(deps Deps) func(context.Context, PlaygroundExplainInput, dashcontract.Principal) (PlaygroundExplainResponse, error) {
	return func(ctx context.Context, in PlaygroundExplainInput, p dashcontract.Principal) (PlaygroundExplainResponse, error) {
		if err := requireEngine(deps); err != nil {
			return PlaygroundExplainResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return PlaygroundExplainResponse{}, err
		}
		// The subject kind is not validated. Warden logs checks under other
		// kinds (the REST API passes "" through, and Go callers pass
		// anything) and the engine evaluates whatever it is given, so a
		// logged check must be replayable here.
		if in.SubjectID == "" {
			return PlaygroundExplainResponse{}, badRequest("subjectId is required")
		}
		if in.Action == "" {
			return PlaygroundExplainResponse{}, badRequest("action is required")
		}
		if in.ResourceType == "" {
			return PlaygroundExplainResponse{}, badRequest("resourceType is required")
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return PlaygroundExplainResponse{}, err
		}

		// TenantID and NamespacePath stay empty on the request: the call
		// options carry them, and they are what the engine trusts.
		req := &warden.CheckRequest{
			Subject: warden.Subject{
				Kind:       warden.SubjectKind(in.SubjectKind),
				ID:         in.SubjectID,
				Attributes: in.SubjectAttributes,
			},
			Action: warden.Action{Name: in.Action},
			Resource: warden.Resource{
				Type:       in.ResourceType,
				ID:         in.ResourceID,
				Attributes: in.ResourceAttributes,
			},
			Context: in.Context,
		}

		start := time.Now()
		// Explain is always a dry run. The option is passed anyway so the
		// intent reads as what it does.
		ex, err := deps.Engine.Explain(ctx, req,
			warden.WithCallTenantID(tenantID),
			warden.WithCallNamespacePath(in.NamespacePath),
			warden.WithCallDryRun(),
		)
		if err != nil {
			return PlaygroundExplainResponse{}, mapWardenError(err)
		}
		return projectExplanation(ex, time.Since(start)), nil
	}
}

// projectExplanation maps the engine's Explanation onto the wire DTO. Every
// array is non-nil, so none serializes as null.
func projectExplanation(ex *warden.Explanation, elapsed time.Duration) PlaygroundExplainResponse {
	out := PlaygroundExplainResponse{
		MatchedBy:   []CheckLogMatch{},
		Obligations: []string{},
		EvalTimeNs:  elapsed.Nanoseconds(),
		Lanes: []PlaygroundLane{
			projectLane("rbac", ex.RBAC),
			projectLane("rebac", ex.ReBAC),
			projectLane("abac", ex.ABAC),
		},
	}
	if ex.Result == nil {
		// A model failed: Check would have returned an error, so nothing was
		// allowed and there is no merged decision to report.
		out.Decision = "error"
		out.Error = ex.Err
		return out
	}
	r := ex.Result
	out.Decision = string(r.Decision)
	out.Allowed = r.Allowed
	out.Reason = r.Reason
	out.EvalTimeNs = r.EvalTimeNs
	out.MatchedBy = projectMatches(r.MatchedBy)
	if len(r.Obligations) > 0 {
		out.Obligations = append(out.Obligations, r.Obligations...)
	}
	return out
}

func projectLane(model string, l warden.Lane) PlaygroundLane {
	out := PlaygroundLane{
		Model:           model,
		State:           string(l.State),
		MatchedBy:       []CheckLogMatch{},
		WalkTruncated:   l.WalkTruncated,
		ExpressionError: l.ExpressionErr,
		Error:           l.Err,
	}
	if l.Result != nil {
		out.Decision = string(l.Result.Decision)
		out.Reason = l.Result.Reason
		out.MatchedBy = projectMatches(l.Result.MatchedBy)
	}
	return out
}

func projectMatches(in []warden.MatchInfo) []CheckLogMatch {
	out := make([]CheckLogMatch, 0, len(in))
	for _, m := range in {
		out = append(out, CheckLogMatch{Source: m.Source, RuleID: m.RuleID, Detail: m.Detail})
	}
	return out
}

// PlaygroundBatchInput is the playground.batchCheck request.
//
// There is no tenant field, on purpose. The tenant is the caller's, resolved
// by tenantFrom.
type PlaygroundBatchInput struct {
	// NamespacePath applies to every item. "" is the root.
	NamespacePath string                `json:"namespacePath"`
	Items         []PlaygroundBatchItem `json:"items"`
}

// PlaygroundBatchItem is one check of a batch.
type PlaygroundBatchItem struct {
	SubjectKind  string `json:"subjectKind"`
	SubjectID    string `json:"subjectId"`
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId,omitempty"`
}

// PlaygroundBatchResult is the outcome of one item.
type PlaygroundBatchResult struct {
	// Decision is "error" when the item's check failed, with Error set.
	Decision string `json:"decision"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
	Error    string `json:"error,omitempty"`
}

// PlaygroundBatchResponse is the playground.batchCheck reply.
type PlaygroundBatchResponse struct {
	// Results is in item order, one per item.
	Results []PlaygroundBatchResult `json:"results"`
}

// defaultMaxBatchChecks is the cap a Config with MaxBatchChecks of 0 gets,
// which is what warden.Config documents ("Defaults to 100"). The extension
// fills the field in, but an engine built by hand with a bare Config keeps 0.
const defaultMaxBatchChecks = 100

// maxBatchChecks is the number of checks one playground batch may hold.
func maxBatchChecks(deps Deps) int {
	if n := deps.Engine.Config().MaxBatchChecks; n > 0 {
		return n
	}
	return defaultMaxBatchChecks
}

// playgroundBatchHandler runs a batch of dry-run checks at one namespace.
//
// Everything is validated before the first item runs, so a refused batch ran
// nothing. Each item then goes through Check, the same dry run
// playground.explain builds: no check log row, no hooks, no cache. One item
// failing does not stop the rest: its result carries decision "error" and
// the engine's own message.
func playgroundBatchHandler(deps Deps) func(context.Context, PlaygroundBatchInput, dashcontract.Principal) (PlaygroundBatchResponse, error) {
	return func(ctx context.Context, in PlaygroundBatchInput, p dashcontract.Principal) (PlaygroundBatchResponse, error) {
		if err := requireEngine(deps); err != nil {
			return PlaygroundBatchResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return PlaygroundBatchResponse{}, err
		}
		if len(in.Items) == 0 {
			return PlaygroundBatchResponse{}, badRequest("items is required")
		}
		if limit := maxBatchChecks(deps); len(in.Items) > limit {
			return PlaygroundBatchResponse{}, badRequest(fmt.Sprintf("a batch holds at most %d checks", limit))
		}
		// The subject kind is not validated, for the reason explain does not
		// validate it: a logged check under any kind must be replayable.
		for i, it := range in.Items {
			switch {
			case it.SubjectID == "":
				return PlaygroundBatchResponse{}, badRequest(fmt.Sprintf("items[%d].subjectId is required", i))
			case it.Action == "":
				return PlaygroundBatchResponse{}, badRequest(fmt.Sprintf("items[%d].action is required", i))
			case it.ResourceType == "":
				return PlaygroundBatchResponse{}, badRequest(fmt.Sprintf("items[%d].resourceType is required", i))
			}
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return PlaygroundBatchResponse{}, err
		}

		results := make([]PlaygroundBatchResult, 0, len(in.Items))
		for _, it := range in.Items {
			// TenantID and NamespacePath stay empty on the request: the call
			// options carry them, and they are what the engine trusts.
			req := &warden.CheckRequest{
				Subject:  warden.Subject{Kind: warden.SubjectKind(it.SubjectKind), ID: it.SubjectID},
				Action:   warden.Action{Name: it.Action},
				Resource: warden.Resource{Type: it.ResourceType, ID: it.ResourceID},
			}
			res, err := deps.Engine.Check(ctx, req,
				warden.WithCallTenantID(tenantID),
				warden.WithCallNamespacePath(in.NamespacePath),
				warden.WithCallDryRun(),
			)
			if err != nil {
				results = append(results, PlaygroundBatchResult{Decision: "error", Error: err.Error()})
				continue
			}
			results = append(results, PlaygroundBatchResult{
				Decision: string(res.Decision),
				Allowed:  res.Allowed,
				Reason:   res.Reason,
			})
		}
		return PlaygroundBatchResponse{Results: results}, nil
	}
}
