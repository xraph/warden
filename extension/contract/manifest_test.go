package contract

import (
	"context"
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
	wreg := dashcontract.NewWardenRegistry()
	if err := wreg.Register(wardenDelegateName, denyAll{}); err != nil {
		t.Fatalf("register delegate: %v", err)
	}
	if err := loader.Validate(m, wreg); err != nil {
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
		"checkLogs.list":              dashcontract.IntentKindQuery,
		"checkLogs.detail":            dashcontract.IntentKindQuery,
		"namespaces.list":             dashcontract.IntentKindQuery,
		"roles.list":                  dashcontract.IntentKindQuery,
		"roles.detail":                dashcontract.IntentKindQuery,
		"roles.create":                dashcontract.IntentKindCommand,
		"roles.update":                dashcontract.IntentKindCommand,
		"roles.delete":                dashcontract.IntentKindCommand,
		"roles.attachPermission":      dashcontract.IntentKindCommand,
		"roles.detachPermission":      dashcontract.IntentKindCommand,
		"roles.setPermissions":        dashcontract.IntentKindCommand,
		"permissions.list":            dashcontract.IntentKindQuery,
		"permissions.detail":          dashcontract.IntentKindQuery,
		"permissions.create":          dashcontract.IntentKindCommand,
		"permissions.update":          dashcontract.IntentKindCommand,
		"permissions.delete":          dashcontract.IntentKindCommand,
		"assignments.list":            dashcontract.IntentKindQuery,
		"assignments.expiring":        dashcontract.IntentKindQuery,
		"assignments.create":          dashcontract.IntentKindCommand,
		"assignments.delete":          dashcontract.IntentKindCommand,
		"relations.list":              dashcontract.IntentKindQuery,
		"relations.create":            dashcontract.IntentKindCommand,
		"relations.delete":            dashcontract.IntentKindCommand,
		"resourceTypes.list":          dashcontract.IntentKindQuery,
		"resourceTypes.detail":        dashcontract.IntentKindQuery,
		"resourceTypes.create":        dashcontract.IntentKindCommand,
		"resourceTypes.update":        dashcontract.IntentKindCommand,
		"resourceTypes.delete":        dashcontract.IntentKindCommand,
		"policies.list":               dashcontract.IntentKindQuery,
		"policies.detail":             dashcontract.IntentKindQuery,
		"policies.validate":           dashcontract.IntentKindQuery,
		"policies.create":             dashcontract.IntentKindCommand,
		"policies.update":             dashcontract.IntentKindCommand,
		"policies.setActive":          dashcontract.IntentKindCommand,
		"policies.delete":             dashcontract.IntentKindCommand,
		"maintenance.run":             dashcontract.IntentKindCommand,
		"maintenance.cacheInvalidate": dashcontract.IntentKindCommand,
		"playground.explain":          dashcontract.IntentKindQuery,
		"playground.batchCheck":       dashcontract.IntentKindQuery,
		"subjects.detail":             dashcontract.IntentKindQuery,
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

// denyAll is a stand-in delegate for tests that only need the manifest to
// validate.
type denyAll struct{}

func (denyAll) Authorize(context.Context, dashcontract.Principal, dashcontract.Action) (dashcontract.Decision, error) {
	return dashcontract.Decision{}, nil
}

func TestManifest_GrantChangesInvalidateThePermissionDetail(t *testing.T) {
	// permissions.detail carries grantedBy, so anything that changes who
	// holds a permission (or how a holder is named) leaves an open
	// permission page stale unless the command says so. The deletes also
	// change the namespace list, which the creates already invalidate.
	m := loadManifest(t)
	byName := map[string][]string{}
	for _, in := range m.Intents {
		byName[in.Name] = in.Invalidates
	}
	has := func(intent, target string) bool {
		for _, v := range byName[intent] {
			if v == target {
				return true
			}
		}
		return false
	}
	for _, intent := range []string{
		"roles.attachPermission", "roles.detachPermission", "roles.setPermissions",
		"roles.update", "roles.delete",
	} {
		if !has(intent, "permissions.detail") {
			t.Errorf("%s does not invalidate permissions.detail", intent)
		}
	}
	for _, intent := range []string{"roles.delete", "permissions.delete"} {
		if !has(intent, "namespaces.list") {
			t.Errorf("%s does not invalidate namespaces.list", intent)
		}
	}
}

func TestManifest_RoleChangesInvalidateTheAssignmentViews(t *testing.T) {
	// AssignmentSummary denormalises roleSlug and roleName, so a rename
	// leaves open assignment pages stale, and a role delete cascades through
	// DeleteAssignmentsByRole into both the list and the expiring feed.
	m := loadManifest(t)
	byName := map[string][]string{}
	for _, in := range m.Intents {
		byName[in.Name] = in.Invalidates
	}
	has := func(intent, target string) bool {
		for _, v := range byName[intent] {
			if v == target {
				return true
			}
		}
		return false
	}
	for _, intent := range []string{"roles.update", "roles.delete"} {
		for _, target := range []string{"assignments.list", "assignments.expiring"} {
			if !has(intent, target) {
				t.Errorf("%s does not invalidate %s", intent, target)
			}
		}
	}
}

func TestManifest_RelationCommandsInvalidateWhatTheyChange(t *testing.T) {
	// A tuple change alters the relation list and the overview counters.
	// namespaces.list is built partly from tuple namespaces (see
	// handlers_namespaces.go), so a create can introduce a namespace and a
	// delete of its last tuple can remove one.
	m := loadManifest(t)
	byName := map[string][]string{}
	for _, in := range m.Intents {
		byName[in.Name] = in.Invalidates
	}
	has := func(intent, target string) bool {
		for _, v := range byName[intent] {
			if v == target {
				return true
			}
		}
		return false
	}
	for _, intent := range []string{"relations.create", "relations.delete"} {
		for _, target := range []string{"relations.list", "overview.stats", "namespaces.list"} {
			if !has(intent, target) {
				t.Errorf("%s does not invalidate %s", intent, target)
			}
		}
	}
}

func TestManifest_RelationListQueryIsDeclared(t *testing.T) {
	m := loadManifest(t)
	q, ok := m.Queries["relationList"]
	if !ok {
		t.Fatal("manifest declares no relationList query")
	}
	if q.Intent != "relations.list" {
		t.Errorf("relationList points at %q, want relations.list", q.Intent)
	}
}

func TestManifest_EveryCommandThatFeedsTheNamespaceListRefreshesIt(t *testing.T) {
	// namespaces.list scans roles, permissions, policies, resource types,
	// assignments and relations (handlers_namespaces.go). A command that
	// creates or deletes one of those can add or drop a namespace, so it must
	// invalidate the list. Assignments were missed once; this pins them and
	// the other writers together so the gap cannot reopen.
	m := loadManifest(t)
	byName := map[string][]string{}
	for _, in := range m.Intents {
		byName[in.Name] = in.Invalidates
	}
	for _, intent := range []string{
		"roles.create", "roles.delete",
		"permissions.create", "permissions.delete",
		"assignments.create", "assignments.delete",
		"relations.create", "relations.delete",
		"resourceTypes.create", "resourceTypes.delete",
		"policies.create", "policies.delete",
		// maintenance.run deletes assignment rows, so it can drop a namespace
		// whose only rows were expired assignments.
		"maintenance.run",
	} {
		found := false
		for _, v := range byName[intent] {
			if v == "namespaces.list" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not invalidate namespaces.list", intent)
		}
	}
}

func TestManifest_MaintenanceRunInvalidatesEverythingItPurges(t *testing.T) {
	// handlers_maintenance.go returns AssignmentsPurged, so the command
	// deletes assignment rows. It used to invalidate only the overview
	// views, which left the assignment list and the expiring feed showing
	// rows that no longer exist. Check logs are its other purge, and they are
	// shown by the recent checks feed and by the check log list and detail.
	m := loadManifest(t)
	var got []string
	for _, in := range m.Intents {
		if in.Name == "maintenance.run" {
			got = in.Invalidates
		}
	}
	for _, target := range []string{
		"overview.stats", "overview.recentChecks", "checkLogs.list", "checkLogs.detail",
		"assignments.list", "assignments.expiring", "roles.detail", "namespaces.list",
	} {
		found := false
		for _, v := range got {
			if v == target {
				found = true
			}
		}
		if !found {
			t.Errorf("maintenance.run does not invalidate %s", target)
		}
	}
}

func TestManifest_CheckLogQueriesAreDeclared(t *testing.T) {
	m := loadManifest(t)
	for name, want := range map[string]struct{ intent, stale string }{
		// Checks arrive continuously, so the list is short-lived. A single
		// check's row never changes once written.
		"checkLogList":   {"checkLogs.list", "10s"},
		"checkLogDetail": {"checkLogs.detail", "60s"},
	} {
		q, ok := m.Queries[name]
		if !ok {
			t.Errorf("manifest declares no %s query", name)
			continue
		}
		if q.Intent != want.intent {
			t.Errorf("%s points at %q, want %s", name, q.Intent, want.intent)
		}
		if q.Cache.StaleTime != want.stale {
			t.Errorf("%s staleTime = %q, want %s", name, q.Cache.StaleTime, want.stale)
		}
	}
	for _, in := range m.Intents {
		if in.Name != "checkLogs.list" && in.Name != "checkLogs.detail" {
			continue
		}
		if in.Kind != dashcontract.IntentKindQuery || in.Capability != "read" {
			t.Errorf("%s is %s/%s, want a read query", in.Name, in.Kind, in.Capability)
		}
	}
}

func TestManifest_ResourceTypeCommandsInvalidateWhatTheyChange(t *testing.T) {
	m := loadManifest(t)
	byName := map[string][]string{}
	for _, in := range m.Intents {
		byName[in.Name] = in.Invalidates
	}
	has := func(intent, target string) bool {
		for _, v := range byName[intent] {
			if v == target {
				return true
			}
		}
		return false
	}
	want := map[string][]string{
		"resourceTypes.create": {"resourceTypes.list", "overview.stats", "namespaces.list"},
		"resourceTypes.update": {"resourceTypes.list", "resourceTypes.detail"},
		"resourceTypes.delete": {"resourceTypes.list", "resourceTypes.detail", "overview.stats", "namespaces.list"},
	}
	for intent, targets := range want {
		for _, target := range targets {
			if !has(intent, target) {
				t.Errorf("%s does not invalidate %s", intent, target)
			}
		}
	}
}

func TestManifest_ResourceTypeQueriesAreDeclared(t *testing.T) {
	m := loadManifest(t)
	for name, intent := range map[string]string{
		"resourceTypeList":   "resourceTypes.list",
		"resourceTypeDetail": "resourceTypes.detail",
	} {
		q, ok := m.Queries[name]
		if !ok {
			t.Errorf("manifest declares no %s query", name)
			continue
		}
		if q.Intent != intent {
			t.Errorf("%s points at %q, want %s", name, q.Intent, intent)
		}
	}
}

func TestManifest_PolicyReadQueriesAreDeclared(t *testing.T) {
	m := loadManifest(t)
	for name, intent := range map[string]string{
		"policyList":   "policies.list",
		"policyDetail": "policies.detail",
	} {
		q, ok := m.Queries[name]
		if !ok {
			t.Errorf("manifest declares no %s query", name)
			continue
		}
		if q.Intent != intent {
			t.Errorf("%s points at %q, want %s", name, q.Intent, intent)
		}
		if q.Cache.StaleTime != "30s" {
			t.Errorf("%s staleTime = %q, want 30s", name, q.Cache.StaleTime)
		}
	}
	for _, in := range m.Intents {
		if in.Name != "policies.list" && in.Name != "policies.detail" {
			continue
		}
		if in.Kind != dashcontract.IntentKindQuery || in.Capability != "read" {
			t.Errorf("%s is %s/%s, want a read query", in.Name, in.Kind, in.Capability)
		}
	}
}

func TestManifest_PolicyValidationIsAQueryThatIsNeverServedStale(t *testing.T) {
	m := loadManifest(t)
	q, ok := m.Queries["policyValidation"]
	if !ok {
		t.Fatal("manifest declares no policyValidation query")
	}
	if q.Intent != "policies.validate" {
		t.Errorf("policyValidation points at %q, want policies.validate", q.Intent)
	}
	if q.Cache.StaleTime != "0s" {
		t.Errorf("policyValidation staleTime = %q, want 0s: a draft answer cannot be reused", q.Cache.StaleTime)
	}
	for _, in := range m.Intents {
		if in.Name == "policies.validate" {
			if in.Kind != dashcontract.IntentKindQuery || in.Capability != "read" {
				t.Errorf("policies.validate is %s/%s, want a read query", in.Kind, in.Capability)
			}
			if len(in.Invalidates) != 0 {
				t.Errorf("a query invalidates nothing, got %v", in.Invalidates)
			}
		}
	}
}

func TestManifest_PlaygroundExplainIsAFreshReadQuery(t *testing.T) {
	m := loadManifest(t)
	q, ok := m.Queries["playgroundExplain"]
	if !ok {
		t.Fatal("manifest declares no playgroundExplain query")
	}
	if q.Intent != "playground.explain" {
		t.Errorf("playgroundExplain points at %q, want playground.explain", q.Intent)
	}
	// Every run must evaluate against the store as it is now.
	if q.Cache.StaleTime != "0s" {
		t.Errorf("playgroundExplain staleTime = %q, want 0s", q.Cache.StaleTime)
	}
	var found bool
	for _, in := range m.Intents {
		if in.Name != "playground.explain" {
			continue
		}
		found = true
		if in.Kind != dashcontract.IntentKindQuery || in.Capability != "read" {
			t.Errorf("playground.explain is %s/%s, want a read query", in.Kind, in.Capability)
		}
		if len(in.Invalidates) != 0 {
			t.Errorf("playground.explain invalidates %v: a query writes nothing", in.Invalidates)
		}
	}
	if !found {
		t.Error("manifest declares no playground.explain intent")
	}
}

func TestManifest_PlaygroundBatchIsAFreshReadQuery(t *testing.T) {
	m := loadManifest(t)
	q, ok := m.Queries["playgroundBatch"]
	if !ok {
		t.Fatal("manifest declares no playgroundBatch query")
	}
	if q.Intent != "playground.batchCheck" {
		t.Errorf("playgroundBatch points at %q, want playground.batchCheck", q.Intent)
	}
	// Every run must evaluate against the store as it is now.
	if q.Cache.StaleTime != "0s" {
		t.Errorf("playgroundBatch staleTime = %q, want 0s", q.Cache.StaleTime)
	}
	var found bool
	for _, in := range m.Intents {
		if in.Name != "playground.batchCheck" {
			continue
		}
		found = true
		if in.Kind != dashcontract.IntentKindQuery || in.Capability != "read" {
			t.Errorf("playground.batchCheck is %s/%s, want a read query", in.Kind, in.Capability)
		}
		if len(in.Invalidates) != 0 {
			t.Errorf("playground.batchCheck invalidates %v: a query writes nothing", in.Invalidates)
		}
	}
	if !found {
		t.Error("manifest declares no playground.batchCheck intent")
	}
}

// subjectDetailInvalidators is every command that can change what
// subjects.detail reports: a subject's resolved roles, the grants of those
// roles, its assignments and relations, the policies that select it, and
// (through maintenance) the rows purged from under it.
var subjectDetailInvalidators = []string{
	"roles.create", "roles.update", "roles.delete",
	"roles.attachPermission", "roles.detachPermission", "roles.setPermissions",
	"permissions.update", "permissions.delete",
	"assignments.create", "assignments.delete",
	"relations.create", "relations.delete",
	"policies.update", "policies.setActive", "policies.delete",
	"maintenance.run",
}

func TestManifest_SubjectDetailIsARefreshedReadQuery(t *testing.T) {
	m := loadManifest(t)
	q, ok := m.Queries["subjectDetail"]
	if !ok {
		t.Fatal("manifest declares no subjectDetail query")
	}
	if q.Intent != "subjects.detail" {
		t.Errorf("subjectDetail points at %q, want subjects.detail", q.Intent)
	}
	if q.Cache.StaleTime != "15s" {
		t.Errorf("subjectDetail staleTime = %q, want 15s", q.Cache.StaleTime)
	}
	found := false
	for _, in := range m.Intents {
		if in.Name != "subjects.detail" {
			continue
		}
		found = true
		if in.Kind != dashcontract.IntentKindQuery || in.Capability != "read" {
			t.Errorf("subjects.detail is %s/%s, want a read query", in.Kind, in.Capability)
		}
		if len(in.Invalidates) != 0 {
			t.Errorf("subjects.detail invalidates %v: a query writes nothing", in.Invalidates)
		}
	}
	if !found {
		t.Error("manifest declares no subjects.detail intent")
	}
}

func TestManifest_EveryCommandThatChangesASubjectsAccessInvalidatesItsDetail(t *testing.T) {
	m := loadManifest(t)
	byName := map[string][]string{}
	for _, in := range m.Intents {
		byName[in.Name] = in.Invalidates
	}
	want := map[string]bool{}
	for _, intent := range subjectDetailInvalidators {
		want[intent] = true
		found := false
		for _, v := range byName[intent] {
			if v == "subjects.detail" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not invalidate subjects.detail", intent)
		}
	}
	// The reverse: nothing else invalidates it without a reason recorded here.
	for name, list := range byName {
		for _, v := range list {
			if v == "subjects.detail" && !want[name] {
				t.Errorf("%s invalidates subjects.detail but is not in subjectDetailInvalidators", name)
			}
		}
	}
}
