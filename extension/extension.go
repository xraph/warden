// Package extension provides a Forge extension entry point for Warden.
package extension

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/xraph/forge"
	"github.com/xraph/vessel"

	"github.com/xraph/warden"
	"github.com/xraph/warden/api"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
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
	config     Config
	eng        *warden.Engine
	apiHandler *api.API
	logger     *slog.Logger
	wardenOpts []warden.Option
	plugins    []plugin.Plugin
}

// New creates a Warden Forge extension with the given options.
func New(opts ...ExtOption) *Extension {
	e := &Extension{}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Name returns the extension name.
func (e *Extension) Name() string { return ExtensionName }

// Description returns the extension description.
func (e *Extension) Description() string { return ExtensionDescription }

// Version returns the extension version.
func (e *Extension) Version() string { return ExtensionVersion }

// Dependencies returns the list of extension names this extension depends on.
func (e *Extension) Dependencies() []string { return []string{} }

// Engine returns the underlying Warden engine.
func (e *Extension) Engine() *warden.Engine { return e.eng }

// API returns the API handler.
func (e *Extension) API() *api.API { return e.apiHandler }

// Register implements [forge.Extension]. It initializes the engine,
// registers it in the DI container, and optionally registers HTTP routes.
func (e *Extension) Register(fapp forge.App) error {
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
	logger := e.logger
	if logger == nil {
		logger = slog.Default()
	}

	// Build warden options.
	opts := make([]warden.Option, 0, len(e.wardenOpts)+len(e.plugins)+2)
	opts = append(opts, warden.WithLogger(logger))

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

	return e.eng.Start(ctx)
}

// Stop gracefully shuts down the warden engine.
func (e *Extension) Stop(ctx context.Context) error {
	if e.eng == nil {
		return nil
	}
	return e.eng.Stop(ctx)
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
