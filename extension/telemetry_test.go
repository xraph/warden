package extension

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel"

	"github.com/xraph/warden"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// newTelemetryApp builds a forge app with a no-op logger and restores the
// global OTel state forge.New replaces.
func newTelemetryApp(t *testing.T, name string) forge.App {
	t.Helper()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return forge.New(forge.WithAppName(name), forge.WithAppLogger(forge.NewNoopLogger()))
}

func scrape(t *testing.T, app forge.App) string {
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

// TestRegister_RecordsMetricsThroughTheApp: the extension hands the app's
// metrics collector to the engine, so a check shows up on the app's
// /_/metrics scrape under forge's prefix.
func TestRegister_RecordsMetricsThroughTheApp(t *testing.T) {
	app := newTelemetryApp(t, "warden-ext-metrics")
	s := memory.New()
	if err := s.CreatePolicy(context.Background(), &policy.Policy{
		TenantID: "t1", Name: "read-docs", Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"read"}, Resources: []string{"doc:*"},
	}); err != nil {
		t.Fatal(err)
	}
	ext := New(WithStore(s), WithDisableRoutes())
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(func() { _ = ext.Engine().Stop(context.Background()) })

	res, err := ext.Engine().Check(context.Background(), &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice@example.com"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "doc", ID: "d1"},
		TenantID: "t1",
	})
	if err != nil || !res.Allowed {
		t.Fatalf("check = %+v, %v", res, err)
	}

	body := scrape(t, app)
	for _, want := range []string{
		`forge_warden_checks_total{cached="false",decision="allow",source="abac"} 1`,
		`forge_warden_check_duration_seconds_count{cached="false",outcome="allow"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %s", want)
		}
	}
}

// TestRegister_EngineLogsThroughTheApp: the engine used to get no logger
// from the extension, so it logged nowhere.
func TestRegister_EngineLogsThroughTheApp(t *testing.T) {
	logger := log.NewTestLogger()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	app := forge.New(forge.WithAppName("warden-ext-logger"), forge.WithAppLogger(logger))

	ext := New(WithStore(memory.New()), WithDisableRoutes())
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Engine().Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ext.Engine().Stop(context.Background()) })

	tl, ok := logger.(*log.TestLogger)
	if !ok {
		t.Fatalf("logger is %T", logger)
	}
	for _, entry := range tl.GetLogs() {
		if entry.Message == "warden: engine starting" {
			return
		}
	}
	t.Fatal("the engine's start line never reached the app logger")
}
