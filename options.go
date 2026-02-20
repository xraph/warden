package warden

import (
	"log/slog"

	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
)

// Option is a functional option for the Engine.
type Option func(*Engine)

// WithStore sets the composite store.
func WithStore(s store.Store) Option { return func(e *Engine) { e.store = s } }

// WithEvaluator sets the ABAC policy evaluator.
func WithEvaluator(ev Evaluator) Option { return func(e *Engine) { e.evaluator = ev } }

// WithGraphWalker sets the ReBAC graph walker.
func WithGraphWalker(gw GraphWalker) Option { return func(e *Engine) { e.graphWalker = gw } }

// WithCache sets the check result cache.
func WithCache(c Cache) Option { return func(e *Engine) { e.cache = c } }

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option { return func(e *Engine) { e.logger = l } }

// WithConfig sets the engine configuration.
func WithConfig(c Config) Option { return func(e *Engine) { e.config = c } }

// WithPlugin registers a plugin with the engine.
func WithPlugin(x plugin.Plugin) Option {
	return func(e *Engine) {
		if e.plugins == nil {
			e.plugins = plugin.NewRegistry(e.logger)
		}
		e.plugins.Register(x)
	}
}
