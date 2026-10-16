package warden

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/forge"
	"go.opentelemetry.io/otel"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// newMetricsApp builds a real forge app for its metrics collector and
// restores the global OTel state forge.New replaces.
func newMetricsApp(t *testing.T) forge.App {
	t.Helper()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return forge.New(forge.WithAppName("warden-metrics-test"), forge.WithAppLogger(forge.NewNoopLogger()))
}

// scrapeMetrics returns the app's Prometheus exposition, as /_/metrics
// serves it.
func scrapeMetrics(t *testing.T, app forge.App) string {
	t.Helper()
	p, ok := app.Metrics().(interface{ PrometheusHandler() http.Handler })
	if !ok {
		t.Fatalf("app metrics %T have no Prometheus handler", app.Metrics())
	}
	rr := httptest.NewRecorder()
	p.PrometheusHandler().ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_/metrics", nil))
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// series returns the sample lines of one metric (name plus a label set),
// without their values, sorted.
func series(body, name string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
			continue
		}
		if i := strings.LastIndexByte(line, ' '); i > 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// sampleValue returns the value of the one sample line that starts with
// prefix, or "" when there is none.
func sampleValue(body, prefix string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix+" ") {
			return strings.TrimPrefix(line, prefix+" ")
		}
	}
	return ""
}

// failingCheckLogStore refuses every check log write.
type failingCheckLogStore struct{ *memory.Store }

func (failingCheckLogStore) CreateCheckLog(context.Context, *checklog.Entry) error {
	return errors.New("check log table unavailable")
}

func TestWithMetricsSink_RecordsThroughForgeMetrics(t *testing.T) {
	app := newMetricsApp(t)
	ctx := context.Background()

	// An allow policy for documents, a cached repeat, a deny, an
	// evaluation failure, and a graph walk stopped at its depth limit.
	s := memory.New()
	if err := s.CreatePolicy(ctx, &policy.Policy{
		TenantID: "t1", Name: "read-docs", Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"read"}, Resources: []string{"doc:*"},
	}); err != nil {
		t.Fatal(err)
	}
	seedDeepChain(t, s, 10)

	cfg := DefaultConfig()
	cfg.CacheTTL = time.Minute
	cfg.MaxGraphDepth = 3
	eng, err := NewEngine(WithStore(failingCheckLogStore{s}), WithConfig(cfg), WithMetricsSink(app.Metrics()))
	if err != nil {
		t.Fatal(err)
	}

	const email = "alice@example.com"
	allow := &CheckRequest{Subject: Subject{Kind: SubjectUser, ID: email}, Action: Action{Name: "read"}, Resource: Resource{Type: "doc", ID: "d1"}, TenantID: "t1"}
	for range 2 {
		if res, err := eng.Check(ctx, allow); err != nil || !res.Allowed {
			t.Fatalf("allow check = %+v, %v", res, err)
		}
	}
	if _, err := eng.Check(ctx, bobViews()); err != nil {
		t.Fatalf("deep chain check: %v", err)
	}

	failing, err := NewEngine(WithStore(failingRoleStore{memory.New()}), WithMetricsSink(app.Metrics()),
		WithConfig(func() Config { c := DefaultConfig(); c.EnableCheckLog = boolPtr(false); return c }()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Check(ctx, &CheckRequest{Subject: Subject{Kind: SubjectUser, ID: email}, Action: Action{Name: "read"}, Resource: Resource{Type: "doc", ID: "d1"}, TenantID: "t1"}); err == nil {
		t.Fatal("expected the failing role store to fail the check")
	}

	// Stop drains the check log writer, so every write has been tried.
	if err := eng.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := failing.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eng.InvalidateTenant(ctx, "t1")

	body := scrapeMetrics(t, app)

	wantChecks := []string{
		`forge_warden_checks_total{cached="false",decision="allow",source="abac"}`,
		`forge_warden_checks_total{cached="false",decision="deny_no_roles",source="none"}`,
		`forge_warden_checks_total{cached="false",decision="error",source="none"}`,
		`forge_warden_checks_total{cached="true",decision="allow",source="abac"}`,
	}
	if got := series(body, "forge_warden_checks_total"); strings.Join(got, "\n") != strings.Join(wantChecks, "\n") {
		t.Errorf("checks series:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantChecks, "\n"))
	}

	wantDuration := []string{
		`forge_warden_check_duration_seconds_count{cached="false",outcome="allow"}`,
		`forge_warden_check_duration_seconds_count{cached="false",outcome="deny"}`,
		`forge_warden_check_duration_seconds_count{cached="false",outcome="error"}`,
		`forge_warden_check_duration_seconds_count{cached="true",outcome="allow"}`,
	}
	if got := series(body, "forge_warden_check_duration_seconds_count"); strings.Join(got, "\n") != strings.Join(wantDuration, "\n") {
		t.Errorf("duration series:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantDuration, "\n"))
	}
	if !strings.Contains(body, `forge_warden_check_duration_seconds_bucket{cached="true",outcome="allow",le="1e-05"}`) {
		t.Error("check duration histogram is missing its sub-millisecond buckets")
	}

	// Three check log writes refused, one role lookup failed.
	if v := sampleValue(body, `forge_warden_store_errors_total{op="create_check_log"}`); v != "3" {
		t.Errorf("create_check_log store errors = %q, want 3", v)
	}
	if v := sampleValue(body, `forge_warden_store_errors_total{op="list_roles_for_subject"}`); v != "1" {
		t.Errorf("list_roles_for_subject store errors = %q, want 1", v)
	}
	if v := sampleValue(body, `forge_warden_graph_depth_exceeded_total`); v != "1" {
		t.Errorf("graph depth exceeded = %q, want 1", v)
	}
	if !strings.Contains(body, `forge_warden_graph_nodes_visited_bucket{le="2500"}`) {
		t.Error("graph nodes histogram is not bucketed for node counts")
	}
	if v := sampleValue(body, `forge_warden_cache_invalidations_total{scope="tenant"}`); v != "1" {
		t.Errorf("tenant cache invalidations = %q, want 1", v)
	}

	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "warden_") {
			continue
		}
		if strings.Contains(line, email) || strings.Contains(line, `"t1"`) || strings.Contains(line, `"doc"`) || strings.Contains(line, `"read"`) {
			t.Errorf("a subject, tenant, resource or action value reached a metric label: %s", line)
		}
	}
}

func TestWithMetricsSink_CheckLogWritesAreCounted(t *testing.T) {
	app := newMetricsApp(t)
	ctx := context.Background()
	eng, err := NewEngine(WithStore(memory.New()), WithMetricsSink(app.Metrics()))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := eng.Check(ctx, bobViews()); err != nil {
			t.Fatal(err)
		}
	}
	if err := eng.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if v := sampleValue(scrapeMetrics(t, app), "forge_warden_checklog_written_total"); v != "3" {
		t.Errorf("check log entries written = %q, want 3", v)
	}
}

func TestWithMetricsSink_NilLeavesMetricsOff(t *testing.T) {
	eng, err := NewEngine(WithStore(memory.New()), WithMetricsSink(nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })
	if _, ok := eng.metrics.(NoopMetrics); !ok {
		t.Fatalf("metrics = %T, want NoopMetrics", eng.metrics)
	}
}

func TestMetricLabels_AreClosedSets(t *testing.T) {
	for d, want := range map[Decision]string{
		DecisionAllow:          "allow",
		DecisionDenyRelation:   "deny_relation",
		DecisionError:          "error",
		Decision("made_up_by"): "other",
	} {
		if got := metricDecision(d); got != want {
			t.Errorf("metricDecision(%q) = %q, want %q", d, got, want)
		}
	}
	for src, want := range map[string]string{"rbac": "rbac", "rebac": "rebac", "abac": "abac", "none": "none", "custom": "other"} {
		if got := metricSource(src); got != want {
			t.Errorf("metricSource(%q) = %q, want %q", src, got, want)
		}
	}
	for d, want := range map[string]string{"allow": "allow", "error": "error", "other": "other", "deny_no_roles": "deny"} {
		if got := checkOutcome(d); got != want {
			t.Errorf("checkOutcome(%q) = %q, want %q", d, got, want)
		}
	}
}

// countingMetrics records StoreError ops and CacheInvalidated scopes.
type countingMetrics struct {
	NoopMetrics
	mu     sync.Mutex
	ops    []string
	scopes []string
}

func (m *countingMetrics) StoreError(op string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops = append(m.ops, op)
}

func (m *countingMetrics) CacheInvalidated(scope string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scopes = append(m.scopes, scope)
}

func (m *countingMetrics) snapshot() (ops, scopes []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ops...), append([]string(nil), m.scopes...)
}

// failingPurgeStore fails every maintenance purge.
type failingPurgeStore struct{ *memory.Store }

func (failingPurgeStore) DeleteExpiredAssignments(context.Context, time.Time) (int64, error) {
	return 0, errors.New("assignments table unavailable")
}

func (failingPurgeStore) DeleteExpiredAssignmentsForTenant(context.Context, string, time.Time) (int64, error) {
	return 0, errors.New("assignments table unavailable")
}

func TestMaintenance_CountsFailedPurgesAsStoreErrors(t *testing.T) {
	m := &countingMetrics{}
	eng, err := NewEngine(WithStore(failingPurgeStore{memory.New()}), WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	if _, err := eng.RunMaintenance(context.Background()); err == nil {
		t.Fatal("expected the purge to fail")
	}
	if _, err := eng.RunTenantMaintenance(context.Background(), "t1"); err == nil {
		t.Fatal("expected the tenant purge to fail")
	}
	// A run cut short by its context ending is not a store failure.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eng.RunMaintenance(cancelled); err == nil {
		t.Fatal("expected the purge to fail")
	}

	ops, _ := m.snapshot()
	want := []string{"delete_expired_assignments", "delete_expired_assignments_for_tenant"}
	if strings.Join(ops, ",") != strings.Join(want, ",") {
		t.Errorf("StoreError ops = %v, want %v", ops, want)
	}
}

func TestCacheInvalidations_AreCountedByScope(t *testing.T) {
	ctx := context.Background()
	m := &countingMetrics{}
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithCache(NewMemoryCache()), WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	// A role delete fires its typed hook (a full clear) and an audit event
	// (a tenant flush). That's one mutation, so it counts once.
	roleID := id.NewRoleID()
	eng.Plugins().EmitRoleDeleted(ctx, roleID)
	eng.Plugins().EmitAudit(ctx, plugin.Event{Action: "role.deleted", TenantID: "t1", EntityID: roleID.String()})

	// A maintenance run that purged something clears everything too.
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1", RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: "expired", ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	eng.nowFn = fakeClock(now)
	if _, err := eng.RunMaintenance(ctx); err != nil {
		t.Fatal(err)
	}
	eng.InvalidateSubject(ctx, "t1", SubjectUser, "u1")

	_, scopes := m.snapshot()
	if want := "tenant,all,subject"; strings.Join(scopes, ",") != want {
		t.Errorf("CacheInvalidated scopes = %v, want %s", scopes, want)
	}
}
