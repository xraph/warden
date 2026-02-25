package extension

import (
	"github.com/xraph/warden"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
)

// Option configures the Warden Forge extension.
type Option func(*Extension)

// WithStore sets the persistence backend.
func WithStore(s store.Store) Option {
	return func(e *Extension) {
		e.wardenOpts = append(e.wardenOpts, warden.WithStore(s))
	}
}

// WithConfig sets the extension configuration.
func WithConfig(cfg Config) Option {
	return func(e *Extension) {
		e.config = cfg
	}
}

// WithEngineOptions adds engine-level options.
func WithEngineOptions(opts ...warden.Option) Option {
	return func(e *Extension) {
		e.wardenOpts = append(e.wardenOpts, opts...)
	}
}

// WithPlugin registers a lifecycle hook plugin.
func WithPlugin(x plugin.Plugin) Option {
	return func(e *Extension) {
		e.plugins = append(e.plugins, x)
	}
}

// WithDisableRoutes disables the registration of HTTP routes.
func WithDisableRoutes() Option {
	return func(e *Extension) {
		e.config.DisableRoutes = true
	}
}

// WithDisableMigrate disables auto-migration on start.
func WithDisableMigrate() Option {
	return func(e *Extension) {
		e.config.DisableMigrate = true
	}
}

// WithBasePath sets the URL prefix for warden routes.
func WithBasePath(path string) Option {
	return func(e *Extension) {
		e.config.BasePath = path
	}
}

// WithRequireConfig requires config to be present in YAML files.
// If true and no config is found, Register returns an error.
func WithRequireConfig() Option {
	return func(e *Extension) {
		e.config.RequireConfig = true
	}
}

// WithGroveDatabase sets the name of the grove.DB to resolve from the DI container.
// The extension will auto-construct the appropriate store backend (postgres/sqlite/mongo)
// based on the grove driver type. Pass an empty string to use the default (unnamed) grove.DB.
func WithGroveDatabase(name string) Option {
	return func(e *Extension) {
		e.config.GroveDatabase = name
		e.useGrove = true
	}
}
