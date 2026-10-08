package extension

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/store/memory"
)

// newTestApp builds a minimal forge.App the way a real host application
// would, with no config files on disk to discover, so Register runs
// against forge's real Register/init path rather than a stand-in.
func newTestApp(name string) forge.App {
	return forge.New(forge.WithAppName(name))
}

// TestRegister_RefusesUnauthenticatedRoutesWithoutInsecureOption exercises
// the real C1 gate directly through Extension.Register (not a copy of its
// logic): routes enabled plus Auth.RequireIdentity=false, with no
// WithInsecureAllowUnauthenticatedRoutes(), must refuse to start rather
// than silently mount an unauthenticated management API.
func TestRegister_RefusesUnauthenticatedRoutesWithoutInsecureOption(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			Auth: AuthConfig{RequireIdentity: false, AuditLog: true},
		}),
	)

	err := ext.Register(newTestApp("gate-a"))
	if err == nil {
		t.Fatal("Register succeeded with routes enabled and RequireIdentity=false and no insecure opt-in; want an error")
	}
	if !strings.Contains(err.Error(), "WithInsecureAllowUnauthenticatedRoutes") {
		t.Fatalf("error does not name the escape hatch option: %v", err)
	}
}

// TestRegister_SucceedsWithInsecureOption is the same configuration as
// above, but with the explicit opt-in: Register must succeed.
func TestRegister_SucceedsWithInsecureOption(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			Auth: AuthConfig{RequireIdentity: false, AuditLog: true},
		}),
		WithInsecureAllowUnauthenticatedRoutes(),
	)

	if err := ext.Register(newTestApp("gate-b")); err != nil {
		t.Fatalf("Register failed with the insecure opt-in set: %v", err)
	}
	if ext.Engine() == nil {
		t.Fatal("Register succeeded but did not construct an engine")
	}
}

// TestRegister_SucceedsWithRequireIdentityFalseWhenRoutesDisabled proves
// Register's gate is specifically about routes being reachable, not about
// the RequireIdentity value in isolation: with DisableRoutes=true Register
// exposes nothing over HTTP, so RequireIdentity=false needs no escape hatch
// to register. Mounting the API afterwards still does (mount_gate_test.go).
func TestRegister_SucceedsWithRequireIdentityFalseWhenRoutesDisabled(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			Auth: AuthConfig{RequireIdentity: false, AuditLog: true},
		}),
		WithDisableRoutes(),
	)

	if err := ext.Register(newTestApp("gate-c")); err != nil {
		t.Fatalf("Register failed with DisableRoutes=true and no insecure opt-in: %v", err)
	}
	if ext.Engine() == nil {
		t.Fatal("Register succeeded but did not construct an engine")
	}
}

// TestRegister_SecureDefaultsNeedNoOptIn is the control case: the
// defaults (RequireIdentity=true) never need the insecure escape hatch,
// with or without routes enabled.
func TestRegister_SecureDefaultsNeedNoOptIn(t *testing.T) {
	ext := New(WithStore(memory.New()))

	if err := ext.Register(newTestApp("gate-d")); err != nil {
		t.Fatalf("Register failed with secure defaults: %v", err)
	}
}

// TestRegister_NegativeRetentionAndIntervalReachTheEngine is the
// programmatic path end to end: WithConfig with negative values must
// validate and arrive at the engine unchanged, not replaced by a default.
func TestRegister_NegativeRetentionAndIntervalReachTheEngine(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{CheckLogRetention: -time.Hour, MaintenanceInterval: -time.Minute}),
		WithDisableRoutes(),
	)
	if err := ext.Register(newTestApp("negative-off")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := ext.Engine().Config()
	if got.CheckLogRetention != -time.Hour || got.MaintenanceInterval != -time.Minute {
		t.Fatalf("engine got retention %v and interval %v, want -1h and -1m", got.CheckLogRetention, got.MaintenanceInterval)
	}
}

// TestRegister_NegativeDurationsLoadFromYAML is the same through a config
// file: a negative duration string must parse and reach the engine.
func TestRegister_NegativeDurationsLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	yaml := "extensions:\n  warden:\n    disable_routes: true\n    check_log_retention: -1h\n    maintenance_interval: -30m\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	app := forge.New(
		forge.WithAppName("negative-off-yaml"),
		forge.WithConfigSearchPaths(dir),
		forge.WithEnableAppScopedConfig(false),
	)
	ext := New(WithStore(memory.New()))
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := ext.Engine().Config()
	if got.CheckLogRetention != -time.Hour || got.MaintenanceInterval != -30*time.Minute {
		t.Fatalf("engine got retention %v and interval %v, want -1h and -30m", got.CheckLogRetention, got.MaintenanceInterval)
	}
}

// yamlApp builds a forge.App whose only config file is a config.yaml in a
// temp dir holding body.
func yamlApp(t *testing.T, name, body string) forge.App {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return forge.New(
		forge.WithAppName(name),
		forge.WithConfigSearchPaths(dir),
		forge.WithEnableAppScopedConfig(false),
	)
}

// TestRegister_YAMLSectionKeepsCodeSetValuesItLeavesOut: a YAML section
// that names none of these keys must not reset what code set to the
// defaults. A key it leaves out keeps the code-set value.
func TestRegister_YAMLSectionKeepsCodeSetValuesItLeavesOut(t *testing.T) {
	requireTenant := false
	app := yamlApp(t, "yaml-keeps-code", "extensions:\n  warden:\n    disable_routes: true\n")
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			CheckLogRetention:   -time.Hour,
			MaintenanceInterval: -time.Minute,
			MaxGraphDepth:       3,
			RequireTenant:       &requireTenant,
		}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := ext.Engine().Config()
	if got.CheckLogRetention != -time.Hour || got.MaintenanceInterval != -time.Minute || got.MaxGraphDepth != 3 {
		t.Fatalf("engine got retention %v, interval %v, depth %d; want -1h, -1m and 3 from code",
			got.CheckLogRetention, got.MaintenanceInterval, got.MaxGraphDepth)
	}
	if got.RequireTenant == nil || *got.RequireTenant {
		t.Errorf("RequireTenant = %v, want the code-set false", got.RequireTenant)
	}
	// Fields neither side set still get the defaults.
	d := DefaultConfig()
	if got.CacheMaxSize != d.CacheMaxSize || got.MaxBatchChecks != d.MaxBatchChecks {
		t.Errorf("cache max size %d, batch %d; want defaults %d and %d",
			got.CacheMaxSize, got.MaxBatchChecks, d.CacheMaxSize, d.MaxBatchChecks)
	}
	if ext.config.Auth != DefaultAuthConfig() {
		t.Errorf("Auth = %+v, want the defaults", ext.config.Auth)
	}
}

// TestRegister_YAMLValueOverridesCode: a key the YAML section sets wins.
// Binding writes a *bool through its pointer, so the caller's own bool
// must not change.
func TestRegister_YAMLValueOverridesCode(t *testing.T) {
	requireTenant := false
	app := yamlApp(t, "yaml-overrides-code", "extensions:\n  warden:\n    disable_routes: true\n"+
		"    max_graph_depth: 5\n    check_log_retention: 2h\n    maintenance_interval: 10m\n    require_tenant: true\n")
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			CheckLogRetention:   -time.Hour,
			MaintenanceInterval: -time.Minute,
			MaxGraphDepth:       3,
			RequireTenant:       &requireTenant,
		}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := ext.Engine().Config()
	if got.CheckLogRetention != 2*time.Hour || got.MaintenanceInterval != 10*time.Minute || got.MaxGraphDepth != 5 {
		t.Fatalf("engine got retention %v, interval %v, depth %d; want 2h, 10m and 5 from YAML",
			got.CheckLogRetention, got.MaintenanceInterval, got.MaxGraphDepth)
	}
	if got.RequireTenant == nil || !*got.RequireTenant {
		t.Errorf("RequireTenant = %v, want YAML's true", got.RequireTenant)
	}
	if requireTenant {
		t.Error("binding YAML changed the caller's own RequireTenant bool")
	}
}

// TestRegister_ExplicitYAMLZeroIsUnset: an explicit 0 in YAML counts as
// unset, so the code-set value fills it, else the default.
func TestRegister_ExplicitYAMLZeroIsUnset(t *testing.T) {
	body := "extensions:\n  warden:\n    disable_routes: true\n    max_graph_depth: 0\n" +
		"    check_log_retention: 0\n    maintenance_interval: 0\n"

	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{CheckLogRetention: -time.Hour, MaxGraphDepth: 3}),
	)
	if err := ext.Register(yamlApp(t, "yaml-zero-code", body)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := ext.Engine().Config()
	d := DefaultConfig()
	if got.CheckLogRetention != -time.Hour || got.MaxGraphDepth != 3 {
		t.Errorf("retention %v, depth %d; want the code-set -1h and 3", got.CheckLogRetention, got.MaxGraphDepth)
	}
	if got.MaintenanceInterval != d.MaintenanceInterval {
		t.Errorf("interval %v, want the default %v (code set none)", got.MaintenanceInterval, d.MaintenanceInterval)
	}

	plain := New(WithStore(memory.New()))
	if err := plain.Register(yamlApp(t, "yaml-zero-plain", body)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got = plain.Engine().Config()
	if got.CheckLogRetention != d.CheckLogRetention || got.MaintenanceInterval != d.MaintenanceInterval ||
		got.MaxGraphDepth != d.MaxGraphDepth {
		t.Errorf("retention %v, interval %v, depth %d; want the defaults",
			got.CheckLogRetention, got.MaintenanceInterval, got.MaxGraphDepth)
	}
}

// TestRegister_NoYAMLSectionUsesCodeThenDefaults: with no warden section
// at all, the code-set values and the defaults apply as before.
func TestRegister_NoYAMLSectionUsesCodeThenDefaults(t *testing.T) {
	app := yamlApp(t, "yaml-other-section", "other:\n  key: value\n")
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{CheckLogRetention: -time.Hour, MaxGraphDepth: 3}),
		WithDisableRoutes(),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := ext.Engine().Config()
	d := DefaultConfig()
	if got.CheckLogRetention != -time.Hour || got.MaxGraphDepth != 3 || got.MaintenanceInterval != d.MaintenanceInterval {
		t.Fatalf("retention %v, depth %d, interval %v; want -1h, 3 and the default %v",
			got.CheckLogRetention, got.MaxGraphDepth, got.MaintenanceInterval, d.MaintenanceInterval)
	}

	plain := New(WithStore(memory.New()), WithDisableRoutes())
	if err := plain.Register(newTestApp("no-config-defaults")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got = plain.Engine().Config()
	if got.CheckLogRetention != d.CheckLogRetention || got.MaxGraphDepth != d.MaxGraphDepth ||
		got.MaintenanceInterval != d.MaintenanceInterval {
		t.Fatalf("no config: retention %v, depth %d, interval %v; want the defaults",
			got.CheckLogRetention, got.MaxGraphDepth, got.MaintenanceInterval)
	}
}

// authYAMLKeys are the two places the loader reads a warden section from.
var authYAMLKeys = []struct{ name, prefix string }{
	{"extensions.warden", "extensions:\n  warden:\n"},
	{"legacy warden", "warden:\n"},
}

// registerWithAuthYAML registers an extension whose code sets codeAuth,
// against a YAML section that disables routes (so a false
// require_identity needs no insecure opt-in) and adds authYAML, which is
// indented under the section. It returns the Auth the extension ended up
// with.
func registerWithAuthYAML(t *testing.T, prefix string, codeAuth AuthConfig, authYAML string) AuthConfig {
	t.Helper()
	body := prefix + "    disable_routes: true\n" + authYAML
	ext := New(WithStore(memory.New()), WithConfig(Config{Auth: codeAuth}))
	if err := ext.Register(yamlApp(t, "auth-yaml", body)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return ext.config.Auth
}

// TestRegister_YAMLAuthKeyWinsOverCode: every auth key the YAML sets wins
// over code, false included, and every key it leaves out keeps the code
// value.
func TestRegister_YAMLAuthKeyWinsOverCode(t *testing.T) {
	type field struct {
		key string
		get func(AuthConfig) bool
		set func(*AuthConfig, bool)
	}
	fields := []field{
		{"require_identity", func(a AuthConfig) bool { return a.RequireIdentity }, func(a *AuthConfig, v bool) { a.RequireIdentity = v }},
		{"allow_anonymous_checks", func(a AuthConfig) bool { return a.AllowAnonymousChecks }, func(a *AuthConfig, v bool) { a.AllowAnonymousChecks = v }},
		{"audit_log", func(a AuthConfig) bool { return a.AuditLog }, func(a *AuthConfig, v bool) { a.AuditLog = v }},
	}
	for _, k := range authYAMLKeys {
		for _, f := range fields {
			for _, yamlVal := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/yaml_%t", k.name, f.key, yamlVal)
				t.Run(name, func(t *testing.T) {
					// Code holds the opposite of the YAML value for this key.
					// The other two keys are true when the YAML says false
					// and false when it says true, except that a code Auth
					// with every field false reads as unset, so the code
					// side keeps one other key on.
					code := AuthConfig{RequireIdentity: !yamlVal, AllowAnonymousChecks: !yamlVal, AuditLog: !yamlVal}
					if yamlVal {
						code = AuthConfig{}
						for _, other := range fields {
							if other.key != f.key {
								other.set(&code, true)
								break
							}
						}
					}
					got := registerWithAuthYAML(t, k.prefix, code,
						fmt.Sprintf("    auth:\n      %s: %t\n", f.key, yamlVal))
					if f.get(got) != yamlVal {
						t.Errorf("%s = %t, want the YAML %t over code %t", f.key, f.get(got), yamlVal, f.get(code))
					}
					for _, other := range fields {
						if other.key != f.key && other.get(got) != other.get(code) {
							t.Errorf("%s = %t, want the code value %t (YAML left it out)", other.key, other.get(got), other.get(code))
						}
					}
				})
			}
		}
	}
}

// TestRegister_YAMLTurnsAnonymousChecksOffOverCode is the exact fail-open
// a review found: code turns anonymous checks on, the YAML turns them off,
// and the result is all three auth fields false. Restoring the code Auth
// because the result is all false would leave anonymous checks on.
func TestRegister_YAMLTurnsAnonymousChecksOffOverCode(t *testing.T) {
	for _, k := range authYAMLKeys {
		t.Run(k.name, func(t *testing.T) {
			code := AuthConfig{RequireIdentity: false, AllowAnonymousChecks: true, AuditLog: false}
			got := registerWithAuthYAML(t, k.prefix, code, "    auth:\n      allow_anonymous_checks: false\n")
			if got != (AuthConfig{}) {
				t.Fatalf("Auth = %+v, want every field false (YAML turned anonymous checks off)", got)
			}
		})
	}
}

// TestRegister_YAMLWithoutAuthKeepsCodeAuth: a section with no auth block
// keeps the code-set Auth as is.
func TestRegister_YAMLWithoutAuthKeepsCodeAuth(t *testing.T) {
	for _, k := range authYAMLKeys {
		t.Run(k.name, func(t *testing.T) {
			code := AuthConfig{RequireIdentity: false, AllowAnonymousChecks: true, AuditLog: false}
			if got := registerWithAuthYAML(t, k.prefix, code, ""); got != code {
				t.Fatalf("Auth = %+v, want the code Auth %+v", got, code)
			}
			if got := registerWithAuthYAML(t, k.prefix, AuthConfig{}, ""); got != DefaultAuthConfig() {
				t.Fatalf("no code Auth: Auth = %+v, want the defaults", got)
			}
		})
	}
}
