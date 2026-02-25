// Package extension provides a Forge extension entry point for Warden.
//
// It implements the forge.Extension interface to integrate Warden
// into a Forge application with automatic dependency discovery,
// route registration, and lifecycle management.
//
// Configuration can be provided programmatically via Option functions
// or via YAML configuration files under "extensions.warden" or "warden" keys.
package extension

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/xraph/forge"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/warden"
	"github.com/xraph/warden/api"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
	mongostore "github.com/xraph/warden/store/mongo"
	pgstore "github.com/xraph/warden/store/postgres"
	sqlitestore "github.com/xraph/warden/store/sqlite"
)

// ExtensionName is the name registered with Forge.
const ExtensionName = "warden"

// ExtensionDescription is the human-readable description.
const ExtensionDescription = "Composable permissions & authorization engine (RBAC, ABAC, ReBAC)"

// ExtensionVersion is the semantic version.
const ExtensionVersion = "0.1.0"

// Ensure Extension implements forge.Extension at compile time.
var _ forge.Extension = (*Extension)(nil)

// Extension adapts Warden as a Forge extension.
type Extension struct {
	*forge.BaseExtension

	config     Config
	eng        *warden.Engine
	apiHandler *api.API
	wardenOpts []warden.Option
	plugins    []plugin.Plugin
	useGrove   bool
}

// New creates a Warden Forge extension with the given options.
func New(opts ...Option) *Extension {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Engine returns the underlying Warden engine.
func (e *Extension) Engine() *warden.Engine { return e.eng }

// API returns the API handler.
func (e *Extension) API() *api.API { return e.apiHandler }

// Register implements [forge.Extension]. It loads configuration,
// initializes the engine, registers it in the DI container, and optionally
// registers HTTP routes.
func (e *Extension) Register(fapp forge.App) error {
	if err := e.BaseExtension.Register(fapp); err != nil {
		return err
	}

	if err := e.loadConfiguration(); err != nil {
		return err
	}

	if err := e.init(fapp); err != nil {
		return err
	}

	// Register the engine in the DI container.
	if err := vessel.Provide(fapp.Container(), func() (*warden.Engine, error) {
		return e.eng, nil
	}); err != nil {
		return fmt.Errorf("warden: register engine in container: %w", err)
	}

	return nil
}

func (e *Extension) init(fapp forge.App) error {
	// Resolve store from grove DI if configured.
	if e.useGrove {
		groveDB, err := e.resolveGroveDB(fapp)
		if err != nil {
			return fmt.Errorf("warden: %w", err)
		}
		s, err := e.buildStoreFromGroveDB(groveDB)
		if err != nil {
			return err
		}
		e.wardenOpts = append(e.wardenOpts, warden.WithStore(s))
	}

	// Build warden options.
	opts := make([]warden.Option, 0, len(e.wardenOpts)+len(e.plugins)+2)

	// Try to resolve store from DI container, fall back to option-provided store.
	if s, err := forge.Inject[store.Store](fapp.Container()); err == nil {
		opts = append(opts, warden.WithStore(s))
	}

	// Append user-provided options (may override store).
	opts = append(opts, e.wardenOpts...)

	// Register extension hooks.
	for _, x := range e.plugins {
		opts = append(opts, warden.WithPlugin(x))
	}

	// Apply max graph depth from config if set.
	if e.config.MaxGraphDepth > 0 {
		opts = append(opts, warden.WithConfig(warden.Config{
			MaxGraphDepth: e.config.MaxGraphDepth,
		}))
	}

	eng, err := warden.NewEngine(opts...)
	if err != nil {
		return fmt.Errorf("warden: create engine: %w", err)
	}
	e.eng = eng

	// Create API handler.
	e.apiHandler = api.New(eng, fapp.Router())

	// Register HTTP routes unless disabled.
	if !e.config.DisableRoutes {
		if err := e.apiHandler.RegisterRoutes(fapp.Router()); err != nil {
			return fmt.Errorf("warden: register routes: %w", err)
		}
	}

	return nil
}

// Start begins the warden engine and runs migrations if enabled.
func (e *Extension) Start(ctx context.Context) error {
	if e.eng == nil {
		return errors.New("warden: extension not initialized")
	}

	// Run migrations unless disabled.
	if !e.config.DisableMigrate {
		s := e.eng.Store()
		if s != nil {
			if err := s.Migrate(ctx); err != nil {
				return fmt.Errorf("warden: migration failed: %w", err)
			}
		}
	}

	if err := e.eng.Start(ctx); err != nil {
		return err
	}

	e.MarkStarted()
	return nil
}

// Stop gracefully shuts down the warden engine.
func (e *Extension) Stop(ctx context.Context) error {
	if e.eng != nil {
		if err := e.eng.Stop(ctx); err != nil {
			e.MarkStopped()
			return err
		}
	}
	e.MarkStopped()
	return nil
}

// Health implements [forge.Extension].
func (e *Extension) Health(ctx context.Context) error {
	if e.eng == nil {
		return errors.New("warden: extension not initialized")
	}
	s := e.eng.Store()
	if s == nil {
		return errors.New("warden: no store configured")
	}
	return s.Ping(ctx)
}

// Handler returns the HTTP handler for all API routes.
func (e *Extension) Handler() http.Handler {
	if e.apiHandler == nil {
		return http.NotFoundHandler()
	}
	return e.apiHandler.Handler()
}

// RegisterRoutes registers all warden API routes into a Forge router.
func (e *Extension) RegisterRoutes(router forge.Router) error {
	if e.apiHandler != nil {
		return e.apiHandler.RegisterRoutes(router)
	}
	return nil
}

// --- Config Loading (mirrors grove extension pattern) ---

// loadConfiguration loads config from YAML files or programmatic sources.
func (e *Extension) loadConfiguration() error {
	programmaticConfig := e.config

	// Try loading from config file.
	fileConfig, configLoaded := e.tryLoadFromConfigFile()

	if !configLoaded {
		if programmaticConfig.RequireConfig {
			return errors.New("warden: configuration is required but not found in config files; " +
				"ensure 'extensions.warden' or 'warden' key exists in your config")
		}

		// Use programmatic config merged with defaults.
		e.config = e.mergeWithDefaults(programmaticConfig)
	} else {
		// Config loaded from YAML -- merge with programmatic options.
		e.config = e.mergeConfigurations(fileConfig, programmaticConfig)
	}

	// Enable grove resolution if YAML config specifies a grove database.
	if e.config.GroveDatabase != "" {
		e.useGrove = true
	}

	e.Logger().Debug("warden: configuration loaded",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
		forge.F("grove_database", e.config.GroveDatabase),
		forge.F("max_graph_depth", e.config.MaxGraphDepth),
	)

	return nil
}

// tryLoadFromConfigFile attempts to load config from YAML files.
func (e *Extension) tryLoadFromConfigFile() (Config, bool) {
	cm := e.App().Config()
	var cfg Config

	// Try "extensions.warden" first (namespaced pattern).
	if cm.IsSet("extensions.warden") {
		if err := cm.Bind("extensions.warden", &cfg); err == nil {
			e.Logger().Debug("warden: loaded config from file",
				forge.F("key", "extensions.warden"),
			)
			return cfg, true
		}
		e.Logger().Warn("warden: failed to bind extensions.warden config",
			forge.F("error", "bind failed"),
		)
	}

	// Try legacy "warden" key.
	if cm.IsSet("warden") {
		if err := cm.Bind("warden", &cfg); err == nil {
			e.Logger().Debug("warden: loaded config from file",
				forge.F("key", "warden"),
			)
			return cfg, true
		}
		e.Logger().Warn("warden: failed to bind warden config",
			forge.F("error", "bind failed"),
		)
	}

	return Config{}, false
}

// mergeWithDefaults fills zero-valued fields with defaults.
func (e *Extension) mergeWithDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.MaxGraphDepth == 0 {
		cfg.MaxGraphDepth = defaults.MaxGraphDepth
	}
	return cfg
}

// mergeConfigurations merges YAML config with programmatic options.
// Programmatic bool flags override when true; YAML takes precedence for value fields.
func (e *Extension) mergeConfigurations(yamlConfig, programmaticConfig Config) Config {
	// Programmatic bool flags override when true.
	if programmaticConfig.DisableRoutes {
		yamlConfig.DisableRoutes = true
	}
	if programmaticConfig.DisableMigrate {
		yamlConfig.DisableMigrate = true
	}

	// String fields: YAML takes precedence.
	if yamlConfig.BasePath == "" && programmaticConfig.BasePath != "" {
		yamlConfig.BasePath = programmaticConfig.BasePath
	}
	if yamlConfig.GroveDatabase == "" && programmaticConfig.GroveDatabase != "" {
		yamlConfig.GroveDatabase = programmaticConfig.GroveDatabase
	}

	// Int fields: YAML takes precedence, programmatic fills gaps.
	if yamlConfig.MaxGraphDepth == 0 && programmaticConfig.MaxGraphDepth != 0 {
		yamlConfig.MaxGraphDepth = programmaticConfig.MaxGraphDepth
	}

	// Fill remaining zeros with defaults.
	return e.mergeWithDefaults(yamlConfig)
}

// resolveGroveDB resolves a *grove.DB from the DI container.
// If GroveDatabase is set, it looks up the named DB; otherwise it uses the default.
func (e *Extension) resolveGroveDB(fapp forge.App) (*grove.DB, error) {
	if e.config.GroveDatabase != "" {
		db, err := vessel.InjectNamed[*grove.DB](fapp.Container(), e.config.GroveDatabase)
		if err != nil {
			return nil, fmt.Errorf("grove database %q not found in container: %w", e.config.GroveDatabase, err)
		}
		return db, nil
	}
	db, err := vessel.Inject[*grove.DB](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove database not found in container: %w", err)
	}
	return db, nil
}

// buildStoreFromGroveDB constructs the appropriate store backend
// based on the grove driver type (pg, sqlite, mongo).
func (e *Extension) buildStoreFromGroveDB(db *grove.DB) (store.Store, error) {
	driverName := db.Driver().Name()
	switch driverName {
	case "pg":
		return pgstore.New(db), nil
	case "sqlite":
		return sqlitestore.New(db), nil
	case "mongo":
		return mongostore.New(db), nil
	default:
		return nil, fmt.Errorf("warden: unsupported grove driver %q", driverName)
	}
}
