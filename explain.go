package warden

import (
	"context"
	"errors"
	"time"
)

// LaneState is what one authorization model did during an explained check.
type LaneState string

const (
	// LaneAllow: the model granted the request.
	LaneAllow LaneState = "allow"
	// LaneDeny: an explicit deny policy matched. ABAC only.
	LaneDeny LaneState = "deny"
	// LaneNoMatch: the model ran and granted nothing. Result carries its
	// reason when it gave one (RBAC and ReBAC always do; ABAC with no
	// matching policy has no result at all).
	LaneNoMatch LaneState = "noMatch"
	// LaneSkipped: ReBAC only. RBAC already allowed and EvaluateAllModels
	// is off, so the graph walk did not run.
	LaneSkipped LaneState = "skipped"
	// LaneDisabled: the model is turned off in Config.
	LaneDisabled LaneState = "disabled"
	// LaneError: the model's store read failed. Check returns an error here.
	LaneError LaneState = "error"
	// LaneNotEvaluated: an earlier model failed, so this one never ran, as
	// in Check.
	LaneNotEvaluated LaneState = "notEvaluated"
)

// Lane is one model's part in an explained check.
type Lane struct {
	State LaneState
	// Result is the model's own result: set for LaneAllow and LaneDeny, and
	// for LaneNoMatch when the model returned one.
	Result *CheckResult
	// Err is the store error, for LaneError.
	Err string
	// WalkTruncated is set on the ReBAC lane when the graph walk stopped at
	// MaxGraphDepth or MaxGraphVisited before it could answer.
	WalkTruncated bool
	// ExpressionErr is set on the ReBAC lane when the resource type's
	// permission expression failed and was treated as no match.
	ExpressionErr string
}

// Explanation is an explained check: the merged result Check would return,
// and each model's own part in it, from one evaluation.
type Explanation struct {
	// Result is what Check would have returned. Nil when a model failed.
	Result *CheckResult
	// Err is the error Check would have returned when a model failed.
	Err               string
	RBAC, ReBAC, ABAC Lane
}

// Explain evaluates req exactly as Check does, as a dry run, and reports
// each model's part. It never reads or fills the cache, fires no hooks and
// writes no check log. A request Check would refuse before evaluating
// (a missing field, a missing tenant) returns that error; a model's store
// failure is reported in the Explanation instead. As in a dry-run Check, a
// store failure still increments Metrics.StoreError and a failed
// permission expression still logs its warning.
func (e *Engine) Explain(ctx context.Context, req *CheckRequest, opts ...CallOption) (*Explanation, error) {
	start := time.Now()
	scope, _, err := e.prepareCheck(ctx, req, opts)
	if err != nil {
		return nil, err
	}
	run := e.runModels(ctx, scope, req)

	out := &Explanation{
		RBAC:  e.lane(e.config.rbacEnabled(), "rbac", run, run.rbac),
		ReBAC: e.rebacLane(run),
		ABAC:  e.lane(e.config.abacEnabled(), "abac", run, run.abac),
	}
	if run.err != nil {
		out.Err = run.err.Error()
		return out, nil
	}
	// mergeDecisions copies the winning lane's struct, so Result is not the
	// lane's pointer, but Result.MatchedBy still shares its backing array
	// with that lane's. Harmless for readers that only marshal it.
	result := e.mergeDecisions(req, run.rbac, run.rebac, run.abac)
	if !result.Allowed && run.rebac != nil && run.rebac.truncated {
		result.Reason = truncatedWalkNote + joinReason(result.Reason)
	}
	result.EvalTimeNs = time.Since(start).Nanoseconds()
	out.Result = result
	return out, nil
}

// modelOrder is each model's position in Check's pipeline, which decides
// whether a failure elsewhere came before it.
var modelOrder = map[string]int{"rbac": 0, "rebac": 1, "abac": 2}

// lane maps one model's part in run to its Lane.
func (e *Engine) lane(enabled bool, model string, run modelRun, result *CheckResult) Lane {
	switch {
	case !enabled:
		return Lane{State: LaneDisabled}
	case run.failed == model:
		return Lane{State: LaneError, Err: unwrapModelErr(run.err)}
	case run.failed != "" && modelOrder[run.failed] < modelOrder[model]:
		return Lane{State: LaneNotEvaluated}
	case result != nil && result.Allowed:
		return Lane{State: LaneAllow, Result: result}
	case result != nil && result.Decision == DecisionDenyExplicit:
		return Lane{State: LaneDeny, Result: result}
	default:
		return Lane{State: LaneNoMatch, Result: result}
	}
}

// rebacLane is lane for ReBAC, which can also be skipped and carries what
// its walk and expression reported. Skipped means exactly Check's own skip
// rule held (RBAC allowed and EvaluateAllModels is off), whatever ABAC did
// afterwards. When RBAC failed, run.rbac is nil and lane reports
// notEvaluated.
func (e *Engine) rebacLane(run modelRun) Lane {
	enabled := e.config.rebacEnabled()
	if enabled && run.rbac != nil && run.rbac.Allowed && !e.config.EvaluateAllModels {
		return Lane{State: LaneSkipped}
	}
	l := e.lane(enabled, "rebac", run, run.rebac)
	if run.rebac != nil {
		l.WalkTruncated = run.rebac.truncated
		l.ExpressionErr = run.rebac.exprErr
	}
	return l
}

// unwrapModelErr returns the store's own message: run.err carries the
// "warden <model>: " prefix Check adds, which the lane already names.
func unwrapModelErr(err error) string {
	if inner := errors.Unwrap(err); inner != nil {
		return inner.Error()
	}
	return err.Error()
}
