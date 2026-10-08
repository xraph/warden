package extension

import (
	"strconv"
	"time"

	"github.com/xraph/forge"
	gometrics "github.com/xraph/go-utils/metrics"

	"github.com/xraph/warden"
)

// forgeMetrics adapts a forge.Metrics factory (an alias for
// github.com/xraph/go-utils/metrics.Metrics) to warden.Metrics. It
// registers the named metrics the SOC2 hardening plan calls for:
//
//	warden_checks_total{decision,source,cached}
//	warden_check_duration_seconds
//	warden_store_errors_total{op}
//	warden_checklog_dropped_total
//	warden_hook_errors_total{hook,plugin}
//	warden_graph_nodes_visited
//	warden_graph_budget_exceeded_total
//	warden_assignments_purged_total
//	warden_checklogs_purged_total
//	warden_cache_invalidations_total{scope}
type forgeMetrics struct {
	checksTotal         gometrics.Counter
	checkDuration       gometrics.Histogram
	storeErrors         gometrics.Counter
	checklogDropped     gometrics.Counter
	hookErrors          gometrics.Counter
	graphNodesVisited   gometrics.Histogram
	graphBudgetExceeded gometrics.Counter
	assignmentsPurged   gometrics.Counter
	checklogsPurged     gometrics.Counter
	cacheInvalidations  gometrics.Counter
}

var _ warden.Metrics = (*forgeMetrics)(nil)

// newForgeMetrics builds the warden.Metrics adapter over m. Passing nil
// is refused by the caller (extension.go falls back to warden.NoopMetrics
// when the host app has no metrics factory configured).
func newForgeMetrics(m forge.Metrics) *forgeMetrics {
	return &forgeMetrics{
		checksTotal:         m.Counter("warden_checks_total"),
		checkDuration:       m.Histogram("warden_check_duration_seconds", gometrics.WithDefaultHistogramBuckets()),
		storeErrors:         m.Counter("warden_store_errors_total"),
		checklogDropped:     m.Counter("warden_checklog_dropped_total"),
		hookErrors:          m.Counter("warden_hook_errors_total"),
		graphNodesVisited:   m.Histogram("warden_graph_nodes_visited"),
		graphBudgetExceeded: m.Counter("warden_graph_budget_exceeded_total"),
		assignmentsPurged:   m.Counter("warden_assignments_purged_total"),
		checklogsPurged:     m.Counter("warden_checklogs_purged_total"),
		cacheInvalidations:  m.Counter("warden_cache_invalidations_total"),
	}
}

func (f *forgeMetrics) CheckEvaluated(decision warden.Decision, source string, dur time.Duration, cached bool) {
	f.checksTotal.WithLabels(map[string]string{
		"decision": string(decision),
		"source":   source,
		"cached":   strconv.FormatBool(cached),
	}).Inc()
	f.checkDuration.Observe(dur.Seconds())
}

func (f *forgeMetrics) StoreError(op string) {
	f.storeErrors.WithLabels(map[string]string{"op": op}).Inc()
}

func (f *forgeMetrics) CheckLogDropped() { f.checklogDropped.Inc() }

// CheckLogWritten has no dedicated named metric in the hardening plan;
// warden_checklog_dropped_total covers the signal an operator needs to
// know check-log writes are falling behind.
func (f *forgeMetrics) CheckLogWritten(int) {}

func (f *forgeMetrics) HookError(hook, pluginName string) {
	f.hookErrors.WithLabels(map[string]string{"hook": hook, "plugin": pluginName}).Inc()
}

func (f *forgeMetrics) GraphNodesVisited(n int) { f.graphNodesVisited.Observe(float64(n)) }

func (f *forgeMetrics) GraphBudgetExceeded() { f.graphBudgetExceeded.Inc() }

func (f *forgeMetrics) AssignmentsPurged(n int64) { f.assignmentsPurged.Add(float64(n)) }

func (f *forgeMetrics) CheckLogsPurged(n int64) { f.checklogsPurged.Add(float64(n)) }

func (f *forgeMetrics) CacheInvalidated(scope string) {
	f.cacheInvalidations.WithLabels(map[string]string{"scope": scope}).Inc()
}
