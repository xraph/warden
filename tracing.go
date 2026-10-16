package warden

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/warden/internal/telemetry"
)

// Span names. None carries an ID; the model in a model span's name is one
// of three fixed values.
const (
	spanCheck         = "check permission"
	spanEvaluateRBAC  = "evaluate rbac"
	spanEvaluateReBAC = "evaluate rebac"
	spanEvaluateABAC  = "evaluate abac"
	spanWalkGraph     = "walk relation graph"
)

// Span attributes. Subjects, resource IDs, tenants and reasons never go on
// a span: a subject ID or resource ID can be a person's ID or email, and a
// reason quotes both. Action and resource type are schema names.
const (
	attrAction         = attribute.Key("warden.action")
	attrResourceType   = attribute.Key("warden.resource.type")
	attrDecision       = attribute.Key("warden.decision")
	attrDecisionSource = attribute.Key("warden.decision.source")
	attrCached         = attribute.Key("warden.cached")
	attrDryRun         = attribute.Key("warden.dry_run")
	attrRBACRoles      = attribute.Key("warden.rbac.roles")
	attrGraphNodes     = attribute.Key("warden.graph.nodes_visited")
	attrGraphOutcome   = attribute.Key("warden.graph.outcome")
)

// checkFacts is what the check span reports beyond the result itself.
type checkFacts struct {
	cached bool
	dryRun bool
}

// endCheckSpan annotates and ends Check's span. Attributes are only built
// when the span is recording, so an unsampled check pays for nothing but
// the span start.
func endCheckSpan(span trace.Span, req *CheckRequest, result *CheckResult, facts checkFacts, err error) {
	if span.IsRecording() {
		span.SetAttributes(
			attrAction.String(req.Action.Name),
			attrResourceType.String(req.Resource.Type),
			attrCached.Bool(facts.cached),
			attrDryRun.Bool(facts.dryRun),
		)
		if err != nil {
			telemetry.MarkError(span, err)
		} else if result != nil {
			span.SetAttributes(
				attrDecision.String(string(result.Decision)),
				attrDecisionSource.String(decisionSource(result)),
			)
		}
	}
	span.End()
}

// endModelSpan annotates and ends one model's span with the decision that
// model reached on its own, or the error it failed with.
func endModelSpan(span trace.Span, result *CheckResult, err error) {
	if span.IsRecording() {
		if err != nil {
			telemetry.MarkError(span, err)
		} else if result != nil {
			span.SetAttributes(attrDecision.String(string(result.Decision)))
		}
	}
	span.End()
}

// walkOutcome names why a graph walk stopped, for the walk span.
func walkOutcome(stop walkStop) string {
	switch stop {
	case walkMatched:
		return "matched"
	case walkDepth:
		return "depth_limit"
	case walkVisited:
		return "visited_limit"
	case walkFanout:
		return "fanout_limit"
	case walkFailed:
		return "error"
	default:
		return "no_path"
	}
}
