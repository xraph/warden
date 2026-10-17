package dsl

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func recordApplySpans(t *testing.T) *tracetest.SpanRecorder {
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

func applySpans(rec *tracetest.SpanRecorder) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() == "apply declarative config" {
			out = append(out, s)
		}
	}
	return out
}

func TestApply_RecordsASpanWithTheChangeCounts(t *testing.T) {
	rec := recordApplySpans(t)
	eng, _ := newTestEngine(t)
	src := []byte(`
warden config 1
tenant tenant-acme

permission "document:read" (document : read)

role viewer {
    name = "Viewer"
    grants = ["document:read"]
}
`)
	prog, diags := Parse("t.warden", src)
	if len(diags) > 0 {
		t.Fatalf("parse: %v", diags)
	}
	res, err := Apply(context.Background(), eng, prog, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	prog, _ = Parse("t.warden", src)
	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{Prune: true}); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	spans := applySpans(rec)
	if len(spans) != 2 {
		t.Fatalf("got %d apply spans, want 2", len(spans))
	}
	first := map[attribute.Key]attribute.Value{}
	for _, kv := range spans[0].Attributes() {
		first[kv.Key] = kv.Value
	}
	if first["warden.apply.created"].AsInt64() != int64(len(res.Created)) || len(res.Created) == 0 {
		t.Errorf("created = %v, want %d", first["warden.apply.created"].AsInt64(), len(res.Created))
	}
	if first["warden.apply.dry_run"].AsBool() || first["warden.apply.prune"].AsBool() {
		t.Errorf("flags = %v", spans[0].Attributes())
	}
	second := map[attribute.Key]attribute.Value{}
	for _, kv := range spans[1].Attributes() {
		second[kv.Key] = kv.Value
	}
	if second["warden.apply.unchanged"].AsInt64() == 0 || !second["warden.apply.prune"].AsBool() {
		t.Errorf("re-apply attributes = %v", spans[1].Attributes())
	}
	for _, s := range spans {
		for _, kv := range s.Attributes() {
			if kv.Value.Type() == attribute.STRING {
				t.Errorf("apply span carries a string attribute %s=%q", kv.Key, kv.Value.AsString())
			}
		}
	}
}

func TestApply_FailedApplyMarksTheSpan(t *testing.T) {
	rec := recordApplySpans(t)
	eng, _ := newTestEngine(t)
	prog, diags := Parse("t.warden", []byte("warden config 1\n"))
	if len(diags) > 0 {
		t.Fatalf("parse: %v", diags)
	}
	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{Prune: true}); err == nil {
		t.Fatal("expected prune without a tenant to be refused")
	}
	spans := applySpans(rec)
	if len(spans) != 1 {
		t.Fatalf("got %d apply spans, want 1", len(spans))
	}
	if st := spans[0].Status(); st.Code != codes.Error || st.Description != "*errors.errorString" {
		t.Errorf("status = %+v, want an error described by its type", st)
	}
}
