package warden

import (
	"strconv"
	"time"

	"github.com/xraph/forge"
	gometrics "github.com/xraph/go-utils/metrics"
)

// WithMetricsSink records the engine's metrics through a go-utils metrics
// collector, the type forge's app.Metrics() returns. It builds the same
// adapter the Forge extension installs, so an engine you construct yourself
// inside a Forge app reports the same series:
//
//	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithMetricsSink(app.Metrics()))
//
// A nil m leaves metrics off. WithMetricsSink and WithMetrics set the same
// sink, so the one passed last wins.
func WithMetricsSink(m gometrics.Metrics) Option {
	return func(e *Engine) {
		if m != nil {
			e.metrics = newSinkMetrics(m)
		}
	}
}

// Metric names, as registered. Forge exports names outside an OTel
// semantic-convention namespace with its own prefix, so each one scrapes as
// forge_<name>.
const (
	metricChecks              = "warden_checks_total"
	metricCheckDuration       = "warden_check_duration_seconds"
	metricStoreErrors         = "warden_store_errors_total"
	metricCheckLogDropped     = "warden_checklog_dropped_total"
	metricCheckLogWritten     = "warden_checklog_written_total"
	metricHookErrors          = "warden_hook_errors_total"
	metricGraphNodesVisited   = "warden_graph_nodes_visited"
	metricGraphBudgetExceeded = "warden_graph_budget_exceeded_total"
	metricGraphDepthExceeded  = "warden_graph_depth_exceeded_total"
	metricAssignmentsPurged   = "warden_assignments_purged_total"
	metricCheckLogsPurged     = "warden_checklogs_purged_total"
	metricCacheInvalidations  = "warden_cache_invalidations_total"
)

// checkDurationBuckets suit an authorization check: a cache hit takes
// microseconds and an uncached check a few store round trips.
var checkDurationBuckets = []float64{
	0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001,
	0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
}

// graphNodeBuckets count nodes, not seconds. The default MaxGraphVisited
// is 5000, so the top bucket sits just past it.
var graphNodeBuckets = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// sinkMetrics adapts a go-utils metrics collector to Metrics. Every series
// is declared once, here, with fixed label names; label values come from
// closed sets (see metricDecision and metricSource), so nothing a caller
// sends can mint a new series.
type sinkMetrics struct {
	checks              *forge.Vec[forge.Counter]
	checkDuration       *forge.Vec[forge.Histogram]
	storeErrors         *forge.Vec[forge.Counter]
	checkLogDropped     forge.Counter
	checkLogWritten     forge.Counter
	hookErrors          *forge.Vec[forge.Counter]
	graphNodesVisited   forge.Histogram
	graphBudgetExceeded forge.Counter
	graphDepthExceeded  forge.Counter
	assignmentsPurged   forge.Counter
	checkLogsPurged     forge.Counter
	cacheInvalidations  *forge.Vec[forge.Counter]
}

var (
	_ Metrics           = (*sinkMetrics)(nil)
	_ GraphDepthMetrics = (*sinkMetrics)(nil)
)

func newSinkMetrics(m gometrics.Metrics) *sinkMetrics {
	return &sinkMetrics{
		checks: forge.CounterVec(m, metricChecks, "decision", "source", "cached"),
		checkDuration: forge.HistogramVec(m, metricCheckDuration, forge.HistogramOpts{
			Buckets: checkDurationBuckets,
			Help:    "Time one Engine.Check took, cache hits included.",
			Unit:    "s",
		}, "cached", "outcome"),
		storeErrors:         forge.CounterVec(m, metricStoreErrors, "op"),
		checkLogDropped:     m.Counter(metricCheckLogDropped),
		checkLogWritten:     m.Counter(metricCheckLogWritten),
		hookErrors:          forge.CounterVec(m, metricHookErrors, "hook", "plugin"),
		graphNodesVisited:   m.Histogram(metricGraphNodesVisited, gometrics.WithBuckets(graphNodeBuckets...)),
		graphBudgetExceeded: m.Counter(metricGraphBudgetExceeded),
		graphDepthExceeded:  m.Counter(metricGraphDepthExceeded),
		assignmentsPurged:   m.Counter(metricAssignmentsPurged),
		checkLogsPurged:     m.Counter(metricCheckLogsPurged),
		cacheInvalidations:  forge.CounterVec(m, metricCacheInvalidations, "scope"),
	}
}

func (s *sinkMetrics) CheckEvaluated(decision Decision, source string, dur time.Duration, cached bool) {
	c := strconv.FormatBool(cached)
	d := metricDecision(decision)
	s.checks.With(d, metricSource(source), c).Inc()
	s.checkDuration.With(c, checkOutcome(d)).Observe(dur.Seconds())
}

func (s *sinkMetrics) StoreError(op string) { s.storeErrors.With(op).Inc() }

func (s *sinkMetrics) CheckLogDropped() { s.checkLogDropped.Inc() }

func (s *sinkMetrics) CheckLogWritten(n int) { s.checkLogWritten.Add(float64(n)) }

func (s *sinkMetrics) HookError(hook, pluginName string) { s.hookErrors.With(hook, pluginName).Inc() }

func (s *sinkMetrics) GraphNodesVisited(n int) { s.graphNodesVisited.Observe(float64(n)) }

func (s *sinkMetrics) GraphBudgetExceeded() { s.graphBudgetExceeded.Inc() }

func (s *sinkMetrics) GraphDepthExceeded() { s.graphDepthExceeded.Inc() }

func (s *sinkMetrics) AssignmentsPurged(n int64) { s.assignmentsPurged.Add(float64(n)) }

func (s *sinkMetrics) CheckLogsPurged(n int64) { s.checkLogsPurged.Add(float64(n)) }

func (s *sinkMetrics) CacheInvalidated(scope string) { s.cacheInvalidations.With(scope).Inc() }

// metricDecision maps a decision to its label value. The engine's own
// decisions pass through; anything else, such as a decision a custom
// Evaluator made up, is "other", so the label stays a closed set.
func metricDecision(d Decision) string {
	switch d {
	case DecisionAllow, DecisionDeny, DecisionDenyExplicit, DecisionDenyDefault,
		DecisionDenyNoRoles, DecisionDenyNoPerms, DecisionDenyCondition,
		DecisionDenyRelation, DecisionError:
		return string(d)
	default:
		return "other"
	}
}

// metricSource maps a decision source to its label value: "rbac", "rebac",
// "abac", "none", or "other" for a source a custom Evaluator named.
func metricSource(source string) string {
	switch source {
	case "rbac", "rebac", "abac", "none":
		return source
	default:
		return "other"
	}
}

// checkOutcome folds a decision label into allow, deny, error or other.
func checkOutcome(decision string) string {
	switch decision {
	case string(DecisionAllow):
		return "allow"
	case string(DecisionError), "other":
		return decision
	default:
		return "deny"
	}
}
