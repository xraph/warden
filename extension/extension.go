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
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/warden"
	"github.com/xraph/warden/api"
	"github.com/xraph/warden/dsl"
	wardencontract "github.com/xraph/warden/extension/contract"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/plugin/auditlog"
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

	// insecureAllowUnauthenticatedRoutes is set only by
	// WithInsecureAllowUnauthenticatedRoutes. With auth.require_identity
	// false, nothing mounts the API without it: Register refuses when routes
	// are enabled, Handler panics, RegisterRoutes returns an error, and the
	// API that API() returns still requires an identity.
	insecureAllowUnauthenticatedRoutes bool
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

// API returns the API handler, or nil before Register. With
// auth.require_identity false and no WithInsecureAllowUnauthenticatedRoutes,
// it still requires an identity on every route: the insecure opt-in is the
// only way to get an API that skips the identity check.
func (e *Extension) API() *api.API { return e.apiHandler }

// errUnauthenticatedAPI refuses to mount the API with auth.require_identity
// false unless WithInsecureAllowUnauthenticatedRoutes was passed. It is nil
// when identity is required or the opt-in is set.
func (e *Extension) errUnauthenticatedAPI() error {
	if e.config.Auth.RequireIdentity || e.insecureAllowUnauthenticatedRoutes {
		return nil
	}
	return errors.New("warden: auth.require_identity is false; " +
		"call extension.WithInsecureAllowUnauthenticatedRoutes() to mount the API without an identity check " +
		"(without it, any network peer could grant roles or read the audit log)")
}

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

	if err := e.config.Validate(); err != nil {
		return fmt.Errorf("warden: %w", err)
	}

	// With routes disabled nothing is mounted here, so an engine-only
	// setup needs no opt-in. Handler and RegisterRoutes run the same check
	// when something mounts the API later.
	if !e.config.DisableRoutes {
		if err := e.errUnauthenticatedAPI(); err != nil {
			return err
		}
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
	} else if db, err := vessel.Inject[*grove.DB](fapp.Container()); err == nil {
		// Auto-discover default grove.DB from container (matches authsome pattern).
		s, err := e.buildStoreFromGroveDB(db)
		if err != nil {
			return err
		}
		e.wardenOpts = append(e.wardenOpts, warden.WithStore(s))
		e.Logger().Info("warden: auto-discovered grove.DB from container",
			forge.F("driver", db.Driver().Name()),
		)
	}

	// Build warden options.
	opts := make([]warden.Option, 0, len(e.wardenOpts)+len(e.plugins)+4)

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

	// Mirror engine knobs (cache, graph budgets, check-log queue/retention,
	// maintenance interval, batch limit, tenant/check-log toggles) straight
	// through: the engine itself auto-builds its memory cache from
	// CacheTTL/CacheMaxSize, so there is no separate cache-construction
	// step here.
	opts = append(opts, warden.WithConfig(e.config.toEngineConfig()))

	// Wire a forge.Metrics-backed warden.Metrics adapter so checks, store
	// errors, cache invalidations, purge counts and hook errors are all
	// observable. e.Metrics() never returns nil (BaseExtension falls back
	// to a no-op collector), so this is unconditional.
	if fm := e.Metrics(); fm != nil {
		opts = append(opts, warden.WithMetrics(newForgeMetrics(fm)))
	}

	// Register the in-tree structured audit-log sink by default (one line
	// per audit event through the extension logger). Registering it here,
	// via WithPlugin, also guarantees the engine's plugin registry exists
	// by the time NewEngine returns, which the invalidator-plugin wiring
	// below depends on.
	if e.config.Auth.AuditLog {
		opts = append(opts, warden.WithPlugin(auditlog.New(e.Logger())))
	}

	eng, err := warden.NewEngine(opts...)
	if err != nil {
		return fmt.Errorf("warden: create engine: %w", err)
	}

	// Wire the DSL expression evaluator into the engine so resource-type
	// permission expressions (`permission read = viewer or parent->view`)
	// are evaluated at Check time. The evaluator is a thin wrapper around
	// the engine's store; it has no internal state besides a per-instance
	// AST cache.
	var ee *dsl.EngineEvaluator
	if s := eng.Store(); s != nil {
		ee = dsl.NewEngineEvaluator(s)
		eng.SetExpressionEvaluator(ee)
	}

	// Register the expression-cache invalidator so an edited or deleted
	// resource type's compiled permission expressions don't keep
	// evaluating against a stale AST. This needs a live plugin registry,
	// which is guaranteed whenever AuditLog is on (the default), a cache
	// is configured, or any plugin was supplied via WithPlugin; in the
	// unusual configuration where none of those apply, there is no
	// registry to attach to and this degrades to a Warn log instead of a
	// nil-pointer panic.
	if ee != nil {
		if reg := eng.Plugins(); reg != nil {
			reg.Register(dsl.NewInvalidatorPlugin(ee.Evaluator()))
		} else {
			e.Logger().Warn("warden: no plugin registry available; expression-cache invalidator not registered " +
				"(enable auth.audit_log, a cache TTL, or register any plugin to get one)")
		}
	}

	e.eng = eng

	// Create the API handler with the configured auth posture.
	apiOpts := make([]api.Option, 0, 2)
	if e.config.Auth.AllowAnonymousChecks {
		apiOpts = append(apiOpts, api.AllowAnonymousChecks())
	}
	if !e.config.Auth.RequireIdentity && e.insecureAllowUnauthenticatedRoutes {
		// Only with the opt-in. Without it, routes are disabled (Register
		// refused otherwise), and the API is built requiring an identity,
		// so whoever mounts it later, through API() or a router of their
		// own, cannot get one without the identity check. Handler and
		// RegisterRoutes refuse outright.
		apiOpts = append(apiOpts, api.WithInsecureAllowUnauthenticatedRoutes())
	}
	e.apiHandler = api.New(eng, fapp.Router(), apiOpts...)

	// Register HTTP routes unless disabled.
	if !e.config.DisableRoutes {
		basePath := e.config.BasePath
		if basePath == "" {
			basePath = "/warden"
		}
		if err := e.apiHandler.RegisterRoutes(fapp.Router().Group(basePath)); err != nil {
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

	// Auto-apply declarative DSL config, if configured. Runs after
	// migrations so the schema is in place; before the engine starts so
	// inbound Check calls see the freshly-applied state.
	if e.config.DeclarativeOnStart {
		if err := e.applyDeclarative(ctx); err != nil {
			if e.config.DeclarativeStrict {
				return fmt.Errorf("warden: declarative apply failed: %w", err)
			}
			e.Logger().Warn("warden: declarative apply error (non-strict, continuing)",
				forge.F("err", err.Error()),
			)
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

// Handler returns the HTTP handler for all API routes, or a handler that
// answers 404 before Register.
//
// It panics when auth.require_identity is false and
// WithInsecureAllowUnauthenticatedRoutes was not passed, the same refusal
// Register returns when routes are enabled: handing out the API would
// otherwise mount it with no opt-in. It has no error to return, and
// api.API.Handler panics on a failed registration the same way.
func (e *Extension) Handler() http.Handler {
	if e.apiHandler == nil {
		return http.NotFoundHandler()
	}
	if err := e.errUnauthenticatedAPI(); err != nil {
		panic(err.Error())
	}
	return e.apiHandler.Handler()
}

// RegisterRoutes registers all warden API routes into a Forge router. It
// registers nothing before Register.
//
// It returns an error, and registers nothing, when auth.require_identity
// is false and WithInsecureAllowUnauthenticatedRoutes was not passed: the
// same refusal Register returns when routes are enabled.
func (e *Extension) RegisterRoutes(router forge.Router) error {
	if e.apiHandler == nil {
		return nil
	}
	if err := e.errUnauthenticatedAPI(); err != nil {
		return err
	}
	return e.apiHandler.RegisterRoutes(router)
}

// --- Config Loading (mirrors grove extension pattern) ---

// loadConfiguration loads config from YAML files or programmatic sources.
func (e *Extension) loadConfiguration() error {
	programmaticConfig := e.config

	// Try loading from config file. The YAML is bound over the code-set
	// config (defaults filling its gaps), so a key the YAML section leaves
	// out keeps the value set in code rather than falling back to a default.
	fileConfig, configLoaded, bindErr := e.tryLoadFromConfigFile(e.mergeWithDefaults(programmaticConfig))

	if bindErr != nil && programmaticConfig.RequireConfig {
		return fmt.Errorf("warden: bind configuration: %w", bindErr)
	}

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
		forge.F("auth_require_identity", e.config.Auth.RequireIdentity),
		forge.F("auth_allow_anonymous_checks", e.config.Auth.AllowAnonymousChecks),
		forge.F("auth_audit_log", e.config.Auth.AuditLog),
	)

	return nil
}

// tryLoadFromConfigFile attempts to load config from YAML files. Each bind
// starts from a copy of base (the code-set config with defaults filling
// its gaps), and the binder only overwrites keys actually present in the
// source document. So a key the YAML section sets wins, and a key it
// leaves out keeps the code-set value, or the default when code set none.
// A YAML section that mentions disable_routes but not auth still keeps
// auth.require_identity=true, rather than zeroing it because the key
// wasn't spelled out. The third return value is the bind error, if any;
// the caller decides whether that's fatal (RequireConfig) or a
// fall-through to defaults.
func (e *Extension) tryLoadFromConfigFile(base Config) (Config, bool, error) {
	cm := e.App().Config()
	var lastErr error

	// Try "extensions.warden" first (namespaced pattern).
	if cm.IsSet("extensions.warden") {
		cfg := base.clone()
		err := cm.Bind("extensions.warden", &cfg)
		if err == nil {
			e.Logger().Debug("warden: loaded config from file",
				forge.F("key", "extensions.warden"),
			)
			return cfg, true, nil
		}
		lastErr = err
		e.Logger().Warn("warden: failed to bind extensions.warden config",
			forge.F("error", err.Error()),
		)
	}

	// Try legacy "warden" key.
	if cm.IsSet("warden") {
		cfg := base.clone()
		err := cm.Bind("warden", &cfg)
		if err == nil {
			e.Logger().Debug("warden: loaded config from file",
				forge.F("key", "warden"),
			)
			return cfg, true, nil
		}
		lastErr = err
		e.Logger().Warn("warden: failed to bind warden config",
			forge.F("error", err.Error()),
		)
	}

	return Config{}, false, lastErr
}

// mergeWithDefaults fills zero-valued fields with defaults. Only an exact 0
// is replaced: a negative CheckLogRetention or MaintenanceInterval is how a
// caller switches purging or the maintenance loop off, so it passes through
// to the engine untouched.
func (e *Extension) mergeWithDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.MaxGraphDepth == 0 {
		cfg.MaxGraphDepth = defaults.MaxGraphDepth
	}
	if cfg.CacheMaxSize == 0 {
		cfg.CacheMaxSize = defaults.CacheMaxSize
	}
	if cfg.MaxGraphVisited == 0 {
		cfg.MaxGraphVisited = defaults.MaxGraphVisited
	}
	if cfg.MaxGraphFanout == 0 {
		cfg.MaxGraphFanout = defaults.MaxGraphFanout
	}
	if cfg.CheckLogQueueSize == 0 {
		cfg.CheckLogQueueSize = defaults.CheckLogQueueSize
	}
	if cfg.CheckLogRetention == 0 {
		cfg.CheckLogRetention = defaults.CheckLogRetention
	}
	if cfg.MaintenanceInterval == 0 {
		cfg.MaintenanceInterval = defaults.MaintenanceInterval
	}
	if cfg.MaxBatchChecks == 0 {
		cfg.MaxBatchChecks = defaults.MaxBatchChecks
	}
	// Auth is only defaulted wholesale when it was never touched at all
	// (code set no Auth, or one with every field false, which reads the
	// same). That fills the base tryLoadFromConfigFile binds over, so a
	// YAML-sourced Auth starts from the code-set Auth, else the defaults.
	// mergeConfigurations keeps the YAML-sourced Auth as bound, all false
	// included, and never lets this line replace it.
	if cfg.Auth == (AuthConfig{}) {
		cfg.Auth = defaults.Auth
	}
	return cfg
}

// mergeConfigurations merges YAML config with programmatic options.
// yamlConfig was bound over the code-set config, so a key the YAML left
// out already holds the code-set value. What is left here: programmatic
// DisableRoutes, DisableMigrate and EvaluateAllModels win when true, and
// an explicit YAML 0 or empty value for the fields below counts as unset,
// so the code-set value fills it, else mergeWithDefaults' default. Auth
// has no such rule: every auth key the YAML sets wins, false included.
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

	// Int/duration fields: YAML takes precedence, programmatic fills gaps.
	if yamlConfig.MaxGraphDepth == 0 && programmaticConfig.MaxGraphDepth != 0 {
		yamlConfig.MaxGraphDepth = programmaticConfig.MaxGraphDepth
	}
	if yamlConfig.CacheTTL == 0 && programmaticConfig.CacheTTL != 0 {
		yamlConfig.CacheTTL = programmaticConfig.CacheTTL
	}
	if yamlConfig.CacheMaxSize == 0 && programmaticConfig.CacheMaxSize != 0 {
		yamlConfig.CacheMaxSize = programmaticConfig.CacheMaxSize
	}
	if yamlConfig.MaxGraphVisited == 0 && programmaticConfig.MaxGraphVisited != 0 {
		yamlConfig.MaxGraphVisited = programmaticConfig.MaxGraphVisited
	}
	if yamlConfig.MaxGraphFanout == 0 && programmaticConfig.MaxGraphFanout != 0 {
		yamlConfig.MaxGraphFanout = programmaticConfig.MaxGraphFanout
	}
	if yamlConfig.CheckLogQueueSize == 0 && programmaticConfig.CheckLogQueueSize != 0 {
		yamlConfig.CheckLogQueueSize = programmaticConfig.CheckLogQueueSize
	}
	if yamlConfig.CheckLogRetention == 0 && programmaticConfig.CheckLogRetention != 0 {
		yamlConfig.CheckLogRetention = programmaticConfig.CheckLogRetention
	}
	if yamlConfig.MaintenanceInterval == 0 && programmaticConfig.MaintenanceInterval != 0 {
		yamlConfig.MaintenanceInterval = programmaticConfig.MaintenanceInterval
	}
	if yamlConfig.MaxBatchChecks == 0 && programmaticConfig.MaxBatchChecks != 0 {
		yamlConfig.MaxBatchChecks = programmaticConfig.MaxBatchChecks
	}
	if yamlConfig.RequireTenant == nil {
		yamlConfig.RequireTenant = programmaticConfig.RequireTenant
	}
	if yamlConfig.EnableCheckLog == nil {
		yamlConfig.EnableCheckLog = programmaticConfig.EnableCheckLog
	}
	if !yamlConfig.EvaluateAllModels && programmaticConfig.EvaluateAllModels {
		yamlConfig.EvaluateAllModels = true
	}

	// Fill remaining zeros with defaults, except Auth. yamlConfig.Auth was
	// bound key by key over the code-set Auth (else the defaults), so it
	// already holds every key the YAML set and the code value for every
	// key it left out. An all-false Auth here is what the YAML asked for,
	// and replacing it with the code or default Auth would undo a setting
	// the YAML made: code AllowAnonymousChecks=true would survive a YAML
	// allow_anonymous_checks: false.
	auth := yamlConfig.Auth
	merged := e.mergeWithDefaults(yamlConfig)
	merged.Auth = auth
	return merged
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
// applyDeclarative loads .warden source(s) from the configured paths and
// applies them to the engine. Called from Start when DeclarativeOnStart
// is set.
func (e *Extension) applyDeclarative(ctx context.Context) error {
	paths := append([]string{}, e.config.DeclarativePaths...)
	if e.config.DeclarativePath != "" {
		paths = append(paths, e.config.DeclarativePath)
	}
	if len(paths) == 0 {
		return errors.New("warden: declarative_on_start set but no declarative_path/paths configured")
	}

	merged := &dsl.Program{}
	var allDiags []*dsl.Diagnostic
	for _, p := range paths {
		prog, diags, err := dsl.Load(p)
		if err != nil {
			return fmt.Errorf("warden: load %s: %w", p, err)
		}
		allDiags = append(allDiags, diags...)
		mergeDeclProgram(merged, prog)
	}
	allDiags = append(allDiags, dsl.Resolve(merged)...)
	if len(allDiags) > 0 {
		for _, d := range allDiags {
			e.Logger().Warn("warden: declarative diagnostic", forge.F("msg", d.String()))
		}
		// On any diagnostic the apply still tries to proceed; Apply will
		// re-run Resolve and bail if there are real errors.
	}

	result, err := dsl.Apply(ctx, e.eng, merged, dsl.ApplyOptions{
		TenantID: e.config.DeclarativeTenantID,
		Prune:    e.config.DeclarativePrune,
	})
	if err != nil {
		return err
	}
	e.Logger().Info("warden: declarative apply complete",
		forge.F("created", len(result.Created)),
		forge.F("updated", len(result.Updated)),
		forge.F("deleted", len(result.Deleted)),
		forge.F("noops", result.NoOps),
	)
	return nil
}

// mergeDeclProgram folds two parsed Programs together. Later wins on
// scope-collision, but the resolver will catch genuine conflicts on
// duplicate slugs/names within the merged result.
func mergeDeclProgram(dst, src *dsl.Program) {
	if dst.Version == 0 {
		dst.Version = src.Version
	}
	if dst.Tenant == "" {
		dst.Tenant = src.Tenant
	}
	if dst.App == "" {
		dst.App = src.App
	}
	dst.ResourceTypes = append(dst.ResourceTypes, src.ResourceTypes...)
	dst.Permissions = append(dst.Permissions, src.Permissions...)
	dst.Roles = append(dst.Roles, src.Roles...)
	dst.Policies = append(dst.Policies, src.Policies...)
	dst.Relations = append(dst.Relations, src.Relations...)
	// Namespaces are already flattened into the lists above. They are kept
	// because Prune reads them: a `namespace` block, even an empty one,
	// covers that namespace.
	dst.Namespaces = append(dst.Namespaces, src.Namespaces...)
}

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

// ─── Dashboard Integration ───────────────────────────────────────────────────

// RegisterContractContributor implements the dashboard's contract
// auto-discovery. It registers the `warden` contributor so the React shell
// can read warden's intents.
func (e *Extension) RegisterContractContributor(
	disp *dispatcher.Dispatcher,
	reg dashcontract.Registry,
	wreg dashcontract.WardenRegistry,
) error {
	if e.eng == nil {
		e.Logger().Warn("warden: engine not initialised; skipping contract contributor registration")
		return nil
	}
	if err := wardencontract.Register(disp, reg, wreg, wardencontract.Deps{Engine: e.eng, DefaultTenantID: e.config.Dashboard.TenantID}); err != nil {
		return fmt.Errorf("warden: register contract contributor: %w", err)
	}
	return nil
}
