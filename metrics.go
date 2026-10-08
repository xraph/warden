package warden

import "time"

// Metrics receives instrumentation events from the engine. Implement this
// interface to wire warden into your metrics backend (Prometheus,
// OpenTelemetry, statsd, ...). WithMetrics installs a custom implementation;
// NoopMetrics is the default when none is configured.
type Metrics interface {
	// CheckEvaluated is called once per Check, whether it hit the cache or
	// was fully evaluated.
	CheckEvaluated(decision Decision, source string, dur time.Duration, cached bool)

	// StoreError is called when a store call returns an error during
	// evaluation. op names the failing operation (e.g. "list_roles").
	StoreError(op string)

	// CheckLogDropped is called when the check log writer's queue is full
	// and an entry is dropped rather than written.
	CheckLogDropped()

	// CheckLogWritten is called after a batch of check log entries is
	// flushed to the store. n is the batch size.
	CheckLogWritten(n int)

	// HookError is called when a plugin hook panics or returns an error.
	HookError(hook, plugin string)

	// GraphNodesVisited is called after a ReBAC graph walk completes with
	// the number of nodes visited during that walk.
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
	// scope is "tenant" or "subject".
	CacheInvalidated(scope string)
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

// compile-time interface check.
var _ Metrics = NoopMetrics{}

// WithMetrics sets the engine's metrics sink.
func WithMetrics(m Metrics) Option {
	return func(e *Engine) {
		if m != nil {
			e.metrics = m
		}
	}
}
