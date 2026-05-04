package warden

import (
	log "github.com/xraph/go-utils/log"

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

// WithExpressionEvaluator sets the resource-type permission expression
// evaluator. The DSL package's NewEngineEvaluator is the canonical
// implementation. When unset, resource-type expressions are inert.
func WithExpressionEvaluator(ev ExpressionEvaluator) Option {
	return func(e *Engine) { e.exprEval = ev }
}

// WithCache sets the check result cache.
func WithCache(c Cache) Option { return func(e *Engine) { e.cache = c } }

// WithLogger sets the structured logger.
func WithLogger(l log.Logger) Option { return func(e *Engine) { e.logger = l } }

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
