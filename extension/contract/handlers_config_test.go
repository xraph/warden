package contract

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func testEngine(t *testing.T, cfg warden.Config) *warden.Engine {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(memory.New()), warden.WithConfig(cfg))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

func TestConfigDetailReportsTheEngineConfig(t *testing.T) {
	falseVal := false
	eng := testEngine(t, warden.Config{
		MaxGraphDepth:     7,
		CacheTTL:          30 * time.Second,
		EnableCheckLog:    &falseVal,
		CheckLogRetention: 48 * time.Hour,
	})

	h := configDetailHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}

	if got.MaxGraphDepth != 7 {
		t.Errorf("maxGraphDepth = %d, want 7", got.MaxGraphDepth)
	}
	// The banner on the config page keys off this exact field. An empty
	// check log is otherwise indistinguishable from an idle system.
	if got.CheckLogEnabled {
		t.Error("checkLogEnabled = true, want false")
	}
	if got.CacheTTLSeconds != 30 {
		t.Errorf("cacheTtlSeconds = %d, want 30", got.CacheTTLSeconds)
	}
	if got.CheckLogRetentionHours != 48 || got.CheckLogRetentionSeconds != 48*3600 {
		t.Errorf("retention hours %d, seconds %d; want 48 and %d", got.CheckLogRetentionHours, got.CheckLogRetentionSeconds, 48*3600)
	}
}

func TestConfigDetailCarriesASubHourRetentionExactly(t *testing.T) {
	// The hours field rounds down, so a 30 minute retention reads 0 there,
	// which a client shows as "kept forever". The seconds fields carry it.
	eng := testEngine(t, warden.Config{
		CheckLogRetention:   30 * time.Minute,
		MaintenanceInterval: 45 * time.Second,
	})
	got, err := configDetailHandler(Deps{Engine: eng})(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}
	if got.CheckLogRetentionSeconds != 1800 || got.CheckLogRetentionHours != 0 {
		t.Errorf("retention seconds %d, hours %d; want 1800 and 0", got.CheckLogRetentionSeconds, got.CheckLogRetentionHours)
	}
	if got.MaintenanceIntervalSeconds != 45 || got.MaintenanceIntervalMin != 0 {
		t.Errorf("interval seconds %d, minutes %d; want 45 and 0", got.MaintenanceIntervalSeconds, got.MaintenanceIntervalMin)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"checkLogRetentionSeconds":   1800,
		"maintenanceIntervalSeconds": 45,
		"checkLogRetentionHours":     0,
		"maintenanceIntervalMinutes": 0,
	} {
		if wire[key] != want {
			t.Errorf("%s = %v, want %v", key, wire[key], want)
		}
	}
}

func TestConfigDetailNeverRoundsAPositiveDurationToZero(t *testing.T) {
	for _, d := range []time.Duration{time.Nanosecond, 999 * time.Millisecond, time.Second, 1500 * time.Millisecond} {
		if got := ceilSeconds(d); got < 1 {
			t.Errorf("ceilSeconds(%s) = %d, want at least 1", d, got)
		}
	}
	if got := ceilSeconds(0); got != 0 {
		t.Errorf("ceilSeconds(0) = %d, want 0", got)
	}
}

func TestConfigDetailDefaultsAreReportedAsEnabled(t *testing.T) {
	// Every Enable* flag is a *bool where nil means enabled. A handler that
	// dereferences it naively panics; one that treats nil as false reports
	// a correctly-configured engine as switched off.
	eng := testEngine(t, warden.Config{})

	h := configDetailHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}

	if !got.RBACEnabled || !got.ABACEnabled || !got.ReBACEnabled || !got.CheckLogEnabled {
		t.Errorf("nil Enable* flags must report enabled, got %+v", got)
	}
}

// TestConfigDetailPinnedToWardenDefaultConfig guards against configDetailHandler's
// `enabled()` helper drifting from warden.DefaultConfig().
//
// `enabled()` in handlers_config.go duplicates the five unexported tri-state
// accessors in config.go (rbacEnabled, abacEnabled, rebacEnabled,
// checkLogEnabled, requireTenant), because this package cannot call
// unexported methods on warden.Config. Today every one of DefaultConfig()'s
// five *bool fields is set to an explicit non-nil true. This test pins
// config.detail's report to that fact: if a future change flips one of those
// defaults to false, the hardcoded expectation below fails loudly, forcing
// whoever made the change to also decide whether enabled() (and this test)
// should move with it.
//
// What this cannot catch: config.go's accessors are unexported, so this
// test cannot call rbacEnabled() and friends directly, and it does not
// exercise the engine's actual runtime behaviour (whether RBAC evaluation
// genuinely runs or is skipped). It also cannot catch a change to the "nil
// means enabled" rule itself, since DefaultConfig() always sets these
// pointers to a non-nil value and never leaves them nil; the nil path is
// covered separately by TestConfigDetailDefaultsAreReportedAsEnabled above,
// but that test also only pins enabled()'s own hardcoded rule, not the
// engine's independently-verified behaviour for a nil flag.
func TestConfigDetailPinnedToWardenDefaultConfig(t *testing.T) {
	cfg := warden.DefaultConfig()

	defaults := map[string]*bool{
		"EnableRBAC":     cfg.EnableRBAC,
		"EnableABAC":     cfg.EnableABAC,
		"EnableReBAC":    cfg.EnableReBAC,
		"EnableCheckLog": cfg.EnableCheckLog,
		"RequireTenant":  cfg.RequireTenant,
	}
	for name, flag := range defaults {
		if flag == nil || !*flag {
			t.Fatalf("warden.DefaultConfig().%s = %v, want a non-nil true; config.detail assumes this default is enabled", name, flag)
		}
	}

	eng := testEngine(t, cfg)
	h := configDetailHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}

	if !got.RBACEnabled || !got.ABACEnabled || !got.ReBACEnabled ||
		!got.CheckLogEnabled || !got.RequireTenant {
		t.Errorf("config.detail must report warden.DefaultConfig()'s flags as enabled, got %+v", got)
	}
}

// namedPlugin implements only the base Plugin interface. The registry logs a
// warning for that and keeps it, which is all these tests need.
type namedPlugin string

func (p namedPlugin) Name() string { return string(p) }

func TestConfigDetailListsTheRegisteredPlugin(t *testing.T) {
	// CacheTTL stays 0, so the engine registers no cache invalidator of its
	// own and the registry holds exactly the plugin passed in.
	eng, err := warden.NewEngine(
		warden.WithStore(memory.New()),
		warden.WithConfig(warden.Config{}),
		warden.WithPlugin(namedPlugin("audit-sink")),
	)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	got, err := configDetailHandler(Deps{Engine: eng})(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}
	if !slices.Equal(got.Plugins, []string{"audit-sink"}) {
		t.Errorf("plugins = %q, want [audit-sink]", got.Plugins)
	}
}

func TestConfigDetailListsPluginsTheEngineRegistersItself(t *testing.T) {
	// A cache TTL makes NewEngine register its own cache invalidator. The
	// list is the registry's, so it carries warden's own plugins beside the
	// caller's, sorted by name.
	eng, err := warden.NewEngine(
		warden.WithStore(memory.New()),
		warden.WithConfig(warden.Config{CacheTTL: time.Minute}),
		warden.WithPlugin(namedPlugin("zz-last")),
		warden.WithPlugin(namedPlugin("audit-sink")),
	)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	got, err := configDetailHandler(Deps{Engine: eng})(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}
	want := []string{"audit-sink", "warden-cache-invalidator", "zz-last"}
	if !slices.Equal(got.Plugins, want) {
		t.Errorf("plugins = %q, want %q", got.Plugins, want)
	}
}

func TestConfigDetailWithNoPluginsSendsAnEmptyList(t *testing.T) {
	// No plugin and no cache leaves the engine with no registry at all
	// (Plugins() returns nil). The page reads the field as a list, so the
	// wire must carry [] and never null.
	eng := testEngine(t, warden.Config{})
	if eng.Plugins() != nil {
		t.Fatalf("precondition: want a nil registry, got one with %d plugins", len(eng.Plugins().Plugins()))
	}

	got, err := configDetailHandler(Deps{Engine: eng})(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(wire["plugins"]) != "[]" {
		t.Errorf("plugins on the wire = %s, want []", wire["plugins"])
	}
}

func TestConfigDetailWithoutAnEngineIsUnavailable(t *testing.T) {
	h := configDetailHandler(Deps{})
	_, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err == nil {
		t.Fatal("want an error when no engine is configured")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeUnavailable {
		t.Errorf("want CodeUnavailable, got %v", err)
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
