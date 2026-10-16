package warden

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/warden/internal/telemetry"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/store/memory"
)

// recordSpans installs a span recorder as the global tracer provider for
// the test and restores the previous provider afterwards.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return rec
}

// spanByName returns the one ended span called name, failing the test when
// there isn't exactly one.
func spanByName(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	var found []sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.Name() == name {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %q span, got %d", name, len(found))
	}
	return found[0]
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	out := make(map[attribute.Key]attribute.Value, len(s.Attributes()))
	for _, kv := range s.Attributes() {
		out[kv.Key] = kv.Value
	}
	return out
}

// wantAttrs fails the test unless s carries every attribute in want.
func wantAttrs(t *testing.T, s sdktrace.ReadOnlySpan, want ...attribute.KeyValue) {
	t.Helper()
	got := spanAttrs(s)
	for _, kv := range want {
		if v, ok := got[kv.Key]; !ok || v != kv.Value {
			t.Errorf("%s: %s = %v (present %v), want %v", s.Name(), kv.Key, v.String(), ok, kv.Value.String())
		}
	}
}

// assertNeverRecorded fails the test if any value shows up in a span's
// name, attributes, events or status.
func assertNeverRecorded(t *testing.T, spans []sdktrace.ReadOnlySpan, values ...string) {
	t.Helper()
	for _, s := range spans {
		var texts []string
		texts = append(texts, s.Name(), s.Status().Description)
		for _, kv := range s.Attributes() {
			texts = append(texts, kv.Value.String())
		}
		for _, ev := range s.Events() {
			texts = append(texts, ev.Name)
			for _, kv := range ev.Attributes {
				texts = append(texts, kv.Value.String())
			}
		}
		for _, text := range texts {
			for _, v := range values {
				if strings.Contains(text, v) {
					t.Errorf("span %q recorded %q", s.Name(), v)
				}
			}
		}
	}
}

// inTrace keeps the spans of one trace, so a span some other code emitted
// on the global provider can't confuse an assertion.
func inTrace(spans []sdktrace.ReadOnlySpan, id trace.TraceID) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.SpanContext().TraceID() == id {
			out = append(out, s)
		}
	}
	return out
}

const (
	tracedSubject  = "alice@example.com"
	tracedTenant   = "tenant-acme"
	tracedResource = "contract-7731"
)

func tracedRequest() *CheckRequest {
	return &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: tracedSubject},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: tracedResource},
		TenantID: tracedTenant,
	}
}

func TestCheck_SpanTree(t *testing.T) {
	rec := recordSpans(t)
	s := memory.New()
	if err := s.CreatePolicy(context.Background(), &policy.Policy{
		TenantID: tracedTenant, Name: "read-docs", Effect: policy.EffectAllow, IsActive: true,
		Actions: []string{"read"}, Resources: []string{"doc:*"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.CacheTTL = time.Minute
	eng, err := NewEngine(WithStore(s), WithConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	ctx, parent := telemetry.StartSpan(context.Background(), "handle request")
	if res, err := eng.Check(ctx, tracedRequest()); err != nil || !res.Allowed {
		t.Fatalf("check = %+v, %v", res, err)
	}
	parent.End()

	spans := inTrace(rec.Ended(), parent.SpanContext().TraceID())
	check := spanByName(t, spans, "check permission")
	rbac := spanByName(t, spans, "evaluate rbac")
	rebac := spanByName(t, spans, "evaluate rebac")
	abac := spanByName(t, spans, "evaluate abac")
	walk := spanByName(t, spans, "walk relation graph")

	for _, sp := range []sdktrace.ReadOnlySpan{check, rbac, rebac, abac, walk} {
		if sp.SpanKind() != trace.SpanKindInternal {
			t.Errorf("%s kind = %v, want internal", sp.Name(), sp.SpanKind())
		}
		if sp.InstrumentationScope().Name != "github.com/xraph/warden" {
			t.Errorf("%s scope = %q", sp.Name(), sp.InstrumentationScope().Name)
		}
		if sp.Status().Code != codes.Unset {
			t.Errorf("%s status = %v, want unset", sp.Name(), sp.Status())
		}
	}
	if check.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Error("check span is not a child of the caller's span")
	}
	for _, sp := range []sdktrace.ReadOnlySpan{rbac, rebac, abac} {
		if sp.Parent().SpanID() != check.SpanContext().SpanID() {
			t.Errorf("%s is not a child of the check span", sp.Name())
		}
	}
	if walk.Parent().SpanID() != rebac.SpanContext().SpanID() {
		t.Error("graph walk span is not a child of the rebac span")
	}

	wantAttrs(t, check,
		attribute.String("warden.action", "read"),
		attribute.String("warden.resource.type", "doc"),
		attribute.String("warden.decision", "allow"),
		attribute.String("warden.decision.source", "abac"),
		attribute.Bool("warden.cached", false),
		attribute.Bool("warden.dry_run", false),
	)
	wantAttrs(t, rbac, attribute.String("warden.decision", "deny_no_roles"), attribute.Int("warden.rbac.roles", 0))
	wantAttrs(t, rebac, attribute.String("warden.decision", "deny_relation"))
	wantAttrs(t, abac, attribute.String("warden.decision", "allow"))
	wantAttrs(t, walk, attribute.Int("warden.graph.nodes_visited", 1), attribute.String("warden.graph.outcome", "no_path"))

	// The same check again is a cache hit: one span, no model spans.
	ctx, parent = telemetry.StartSpan(context.Background(), "handle request")
	if _, err := eng.Check(ctx, tracedRequest()); err != nil {
		t.Fatal(err)
	}
	parent.End()
	hit := inTrace(rec.Ended(), parent.SpanContext().TraceID())
	if len(hit) != 2 {
		t.Fatalf("a cache hit recorded %d spans, want the check and its parent", len(hit))
	}
	wantAttrs(t, spanByName(t, hit, "check permission"), attribute.Bool("warden.cached", true), attribute.String("warden.decision", "allow"))

	assertNeverRecorded(t, rec.Ended(), tracedSubject, tracedTenant, tracedResource)
}

func TestCheck_FailedCheckMarksSpansWithoutTheMessage(t *testing.T) {
	rec := recordSpans(t)
	eng, err := NewEngine(WithStore(failingRoleStore{memory.New()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	if _, err := eng.Check(context.Background(), tracedRequest()); err == nil {
		t.Fatal("expected the role lookup failure to fail the check")
	}

	spans := rec.Ended()
	check := spanByName(t, spans, "check permission")
	rbac := spanByName(t, spans, "evaluate rbac")
	if check.Parent().IsValid() {
		t.Error("a check with no caller span should be a root")
	}
	for _, sp := range []sdktrace.ReadOnlySpan{check, rbac} {
		if sp.Status().Code != codes.Error || sp.Status().Description != "*errors.errorString" {
			t.Errorf("%s status = %+v, want an error described by its type", sp.Name(), sp.Status())
		}
		evs := sp.Events()
		if len(evs) != 1 || evs[0].Name != "exception" || len(evs[0].Attributes) != 1 ||
			evs[0].Attributes[0] != attribute.String("exception.type", "*errors.errorString") {
			t.Errorf("%s events = %+v, want one exception event with only its type", sp.Name(), evs)
		}
	}
	if _, ok := spanAttrs(check)["warden.decision"]; ok {
		t.Error("a failed check span carries a decision")
	}
	assertNeverRecorded(t, spans, tracedSubject, tracedTenant, tracedResource, "roles unavailable")
}

func TestCheck_RefusedRequestIsAnErrorSpan(t *testing.T) {
	rec := recordSpans(t)
	eng, err := NewEngine(WithStore(memory.New()), WithConfig(func() Config {
		c := DefaultConfig()
		c.RequireTenant = boolPtr(true)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	req := tracedRequest()
	req.TenantID = ""
	if _, err := eng.Check(context.Background(), req); err == nil {
		t.Fatal("expected a missing tenant to be refused")
	}
	check := spanByName(t, rec.Ended(), "check permission")
	if check.Status().Code != codes.Error || check.Status().Description != "warden.ErrTenantRequired" {
		t.Errorf("status = %+v, want the sentinel's name", check.Status())
	}
	if len(rec.Ended()) != 1 {
		t.Errorf("a refused check recorded %d spans, want 1", len(rec.Ended()))
	}
}

func TestWalk_SpanReportsALimitAsAnOutcome(t *testing.T) {
	rec := recordSpans(t)
	s := memory.New()
	seedDeepChain(t, s, 10)
	cfg := DefaultConfig()
	cfg.MaxGraphDepth = 3
	eng, err := NewEngine(WithStore(s), WithConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	if _, err := eng.Check(context.Background(), bobViews()); err != nil {
		t.Fatal(err)
	}
	walk := spanByName(t, rec.Ended(), "walk relation graph")
	wantAttrs(t, walk, attribute.String("warden.graph.outcome", "depth_limit"), attribute.Int("warden.graph.nodes_visited", 4))
	if walk.Status().Code != codes.Unset {
		t.Errorf("a walk stopped at its depth limit is marked %v", walk.Status())
	}
	assertNeverRecorded(t, rec.Ended(), "bob")
}
