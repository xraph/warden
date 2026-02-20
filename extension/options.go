package extension

import (
	"log/slog"

	"github.com/xraph/warden"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
)

// ExtOption configures the Warden Forge extension.
type ExtOption func(*Extension)

// WithStore sets the persistence backend.
func WithStore(s store.Store) ExtOption {
	return func(e *Extension) {
		e.wardenOpts = append(e.wardenOpts, warden.WithStore(s))
	}
}

// WithConfig sets the extension configuration.
func WithConfig(cfg Config) ExtOption {
	return func(e *Extension) {
		e.config = cfg
	}
}

// WithEngineOptions adds engine-level options.
func WithEngineOptions(opts ...warden.Option) ExtOption {
	return func(e *Extension) {
		e.wardenOpts = append(e.wardenOpts, opts...)
	}
}

// WithPlugin registers a lifecycle hook plugin.
func WithPlugin(x plugin.Plugin) ExtOption {
	return func(e *Extension) {
		e.plugins = append(e.plugins, x)
	}
}

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) ExtOption {
	return func(e *Extension) {
		e.logger = l
	}
}

// WithDisableRoutes disables the registration of HTTP routes.
func WithDisableRoutes() ExtOption {
	return func(e *Extension) {
		e.config.DisableRoutes = true
	}
}

// WithDisableMigrate disables auto-migration on start.
func WithDisableMigrate() ExtOption {
	return func(e *Extension) {
		e.config.DisableMigrate = true
	}
}
