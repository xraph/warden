package contract

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

func loadManifest(t *testing.T) *dashcontract.ContractManifest {
	t.Helper()
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "warden/extension/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func TestManifest_Loads(t *testing.T) {
	m := loadManifest(t)
	if m.Contributor.Name != "warden" {
		t.Errorf("contributor name = %q, want warden", m.Contributor.Name)
	}
}

func TestManifest_Validates(t *testing.T) {
	m := loadManifest(t)
	if err := loader.Validate(m, dashcontract.NewWardenRegistry()); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestManifest_RegistersWithRegistry(t *testing.T) {
	reg := dashcontract.NewRegistry()
	m := loadManifest(t)
	if err := reg.Register(m); err != nil {
		t.Fatalf("register: %v", err)
	}

	wantKind := map[string]dashcontract.IntentKind{
		"config.detail":               dashcontract.IntentKindQuery,
		"overview.stats":              dashcontract.IntentKindQuery,
		"overview.recentChecks":       dashcontract.IntentKindQuery,
		"namespaces.list":             dashcontract.IntentKindQuery,
		"roles.list":                  dashcontract.IntentKindQuery,
		"roles.detail":                dashcontract.IntentKindQuery,
		"roles.create":                dashcontract.IntentKindCommand,
		"roles.update":                dashcontract.IntentKindCommand,
		"roles.delete":                dashcontract.IntentKindCommand,
		"roles.attachPermission":      dashcontract.IntentKindCommand,
		"roles.detachPermission":      dashcontract.IntentKindCommand,
		"roles.setPermissions":        dashcontract.IntentKindCommand,
		"maintenance.run":             dashcontract.IntentKindCommand,
		"maintenance.cacheInvalidate": dashcontract.IntentKindCommand,
	}
	if len(m.Intents) != len(wantKind) {
		t.Fatalf("manifest declares %d intents, want %d: %+v", len(m.Intents), len(wantKind), m.Intents)
	}
	for name, kind := range wantKind {
		intent, ok := reg.Intent(contributorName, name, 1)
		if !ok {
			t.Fatalf("expected %s to be registered", name)
		}
		if intent.Kind != kind {
			t.Errorf("%s kind = %q, want %q", name, intent.Kind, kind)
		}
	}
}

// registerCallPattern matches a dispatcher.RegisterQuery / dispatcher.RegisterCommand
// call in contract.go's Register function, capturing the intent name and
// version it binds a handler to.
var registerCallPattern = regexp.MustCompile(`dispatcher\.Register(?:Query|Command)\(d, contributorName, "([^"]+)", (\d+),`)

// handlerIntentsFromSource parses contract.go's own source and returns every
// (intent name -> version) pair its Register function binds a handler to.
// Reading the real source, rather than keeping a hand-copied list in this
// test, is deliberate: a hand-copied list can drift the moment someone adds
// a handler and forgets to update the test, which is exactly the silent
// failure this test exists to catch.
func handlerIntentsFromSource(t *testing.T) map[string]int {
	t.Helper()
	src, err := os.ReadFile("contract.go")
	if err != nil {
		t.Fatalf("read contract.go: %v", err)
	}
	matches := registerCallPattern.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no dispatcher.Register* calls in contract.go; registerCallPattern may be stale")
	}
	out := make(map[string]int, len(matches))
	for _, match := range matches {
		version, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatalf("parse version from %q: %v", match[0], err)
		}
		out[match[1]] = version
	}
	return out
}

// TestManifest_IntentsMatchDispatcherRegistrations checks the manifest and
// contract.go's handler registrations against each other, in both
// directions. A manifest entry with no handler produces a dashboard page
// that never loads. A handler with no manifest entry is dead code nobody
// can reach, since the dispatcher only accepts requests the manifest
// advertises. Both are silent today: extension.go only logs a registration
// error and carries on, so this is the only thing that will catch either
// mistake as the package grows from six intents toward several dozen across
// the plans that follow.
func TestManifest_IntentsMatchDispatcherRegistrations(t *testing.T) {
	m := loadManifest(t)
	manifestIntents := make(map[string]int, len(m.Intents))
	for _, in := range m.Intents {
		manifestIntents[in.Name] = in.Version
	}

	handlerIntents := handlerIntentsFromSource(t)

	for name, version := range manifestIntents {
		v, ok := handlerIntents[name]
		if !ok {
			t.Errorf("manifest declares intent %q but contract.go registers no handler for it", name)
			continue
		}
		if v != version {
			t.Errorf("intent %q: manifest declares version %d, handler is registered at version %d", name, version, v)
		}
	}
	for name := range handlerIntents {
		if _, ok := manifestIntents[name]; !ok {
			t.Errorf("contract.go registers a handler for intent %q but the manifest does not declare it", name)
		}
	}
}
