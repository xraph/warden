package warden

import "time"

// Metrics receives instrumentation events from the engine. Implement this
// interface to wire warden into your metrics backend (Prometheus,
// OpenTelemetry, statsd, ...). WithMetrics installs a custom implementation,
// and WithMetricsSink installs the built-in one over a go-utils collector
// such as forge's app.Metrics(). NoopMetrics is the default when none is
// configured.
type Metrics interface {
	// CheckEvaluated is called once per Check that got as far as
	// evaluating, whether it hit the cache or was fully evaluated. A check
	// whose evaluation failed reports DecisionError with source "none". A
	// request Check refuses before evaluating (a missing field, a missing
	// tenant) reports nothing.
	CheckEvaluated(decision Decision, source string, dur time.Duration, cached bool)

	// StoreError is called when a store call the engine makes returns an
	// error: during evaluation, while writing the check log, or in a
	// maintenance run. op names the failing operation in snake case (e.g.
	// "list_roles_for_subject", "create_check_log", "purge_check_logs").
	StoreError(op string)

	// CheckLogDropped is called when the check log writer's queue is full
	// and an entry is dropped rather than written.
	CheckLogDropped()

	// CheckLogWritten is called after a batch of check log entries is
	// flushed to the store. n is the number of entries written; one that
	// failed is reported through StoreError("create_check_log") instead.
	CheckLogWritten(n int)

	// HookError is called when a plugin hook panics or returns an error.
	HookError(hook, plugin string)

	// GraphNodesVisited is called after a ReBAC graph walk completes with
	// the number of nodes visited during that walk, including a walk that
	// stopped at a limit. A walk that failed reports nothing.
	GraphNodesVisited(n int)

	// GraphBudgetExceeded is called when a ReBAC graph walk is aborted
	// because it exceeded MaxGraphVisited or MaxGraphFanout.
	GraphBudgetExceeded()

	// AssignmentsPurged is called after a maintenance run purges expired
	// role assignments, with the number of rows removed.
	AssignmentsPurged(n int64)

	// CheckLogsPurged is called after a maintenance run purges old check
	// log entries, with the number of rows removed.
	CheckLogsPurged(n int64)

	// CacheInvalidated is called whenever the check cache is invalidated.
	// scope is "subject", "tenant", or "all" for a full clear.
	CacheInvalidated(scope string)
}

// GraphDepthMetrics is an optional addition to Metrics. When the engine's
// Metrics also implements it, GraphDepthExceeded is called each time a
// ReBAC graph walk stops at MaxGraphDepth. It sits apart from Metrics so an
// implementation written before it existed still compiles. NoopMetrics and
// the WithMetricsSink adapter implement it.
type GraphDepthMetrics interface {
	GraphDepthExceeded()
}

// NoopMetrics implements Metrics with no-ops. It is the default when no
// Metrics is configured via WithMetrics.
type NoopMetrics struct{}

func (NoopMetrics) CheckEvaluated(Decision, string, time.Duration, bool) {}
func (NoopMetrics) StoreError(string)                                    {}
func (NoopMetrics) CheckLogDropped()                                     {}
func (NoopMetrics) CheckLogWritten(int)                                  {}
func (NoopMetrics) HookError(string, string)                             {}
func (NoopMetrics) GraphNodesVisited(int)                                {}
func (NoopMetrics) GraphBudgetExceeded()                                 {}
func (NoopMetrics) AssignmentsPurged(int64)                              {}
func (NoopMetrics) CheckLogsPurged(int64)                                {}
func (NoopMetrics) CacheInvalidated(string)                              {}
func (NoopMetrics) GraphDepthExceeded()                                  {}

// compile-time interface check.
var (
	_ Metrics           = NoopMetrics{}
	_ GraphDepthMetrics = NoopMetrics{}
)

// WithMetrics sets the engine's metrics sink.
func WithMetrics(m Metrics) Option {
	return func(e *Engine) {
		if m != nil {
			e.metrics = m
		}
	}
}
