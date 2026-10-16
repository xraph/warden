package warden

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/internal/telemetry"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// recordSpans installs a span recorder, plus any extra processors, as the
// global tracer provider for the test and restores the previous provider
// afterwards.
func recordSpans(t *testing.T, extra ...sdktrace.SpanProcessor) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	opts := make([]sdktrace.TracerProviderOption, 0, 1+len(extra))
	opts = append(opts, sdktrace.WithSpanProcessor(rec))
	for _, p := range extra {
		opts = append(opts, sdktrace.WithSpanProcessor(p))
	}
	tp := sdktrace.NewTracerProvider(opts...)
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

// endedSpans hands each ended span to a channel, so a test can wait for a
// background span without polling.
type endedSpans chan sdktrace.ReadOnlySpan

func (c endedSpans) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (c endedSpans) OnEnd(s sdktrace.ReadOnlySpan) {
	select {
	case c <- s:
	default:
	}
}
func (endedSpans) Shutdown(context.Context) error   { return nil }
func (endedSpans) ForceFlush(context.Context) error { return nil }

// waitForSpan returns the next ended span called name. The timeout only
// guards against a hang; the test never sleeps.
func waitForSpan(t *testing.T, ch endedSpans, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case s := <-ch:
			if s.Name() == name {
				return s
			}
		case <-timeout:
			t.Fatalf("no %q span ended", name)
			return nil
		}
	}
}

func TestCheckLogWriter_EachFlushIsARootSpan(t *testing.T) {
	for name, tc := range map[string]struct {
		store      checklog.Store
		wantFailed int
	}{
		"written": {store: memory.New()},
		"refused": {store: failingCheckLogStore{memory.New()}, wantFailed: 3},
	} {
		t.Run(name, func(t *testing.T) {
			rec := recordSpans(t)
			w := newCheckLogWriter(tc.store, 10, nil, nil)
			for range 3 {
				w.Enqueue(&checklog.Entry{ID: id.NewCheckLogID(), TenantID: tracedTenant, SubjectKind: "user", SubjectID: tracedSubject, Decision: "allow"})
			}
			if err := w.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}

			var batched, failed int64
			for _, s := range rec.Ended() {
				if s.Name() != "flush check log" {
					continue
				}
				if s.Parent().IsValid() {
					t.Error("a check log flush has a parent span")
				}
				attrs := spanAttrs(s)
				batched += attrs["warden.checklog.batch_size"].AsInt64()
				failed += attrs["warden.checklog.failed"].AsInt64()
				if wantErr := tc.wantFailed > 0; wantErr != (s.Status().Code == codes.Error) {
					t.Errorf("flush status = %+v with %d failures", s.Status(), tc.wantFailed)
				}
			}
			if batched != 3 || failed != int64(tc.wantFailed) {
				t.Errorf("flush spans covered %d entries with %d failed, want 3 and %d", batched, failed, tc.wantFailed)
			}
			assertNeverRecorded(t, rec.Ended(), tracedSubject, tracedTenant, "check log table unavailable")
		})
	}
}

func TestStartMaintenance_EachRunIsARootSpan(t *testing.T) {
	ended := make(endedSpans, 16)
	recordSpans(t, ended)
	eng, err := NewEngine(WithStore(memory.New()), WithConfig(func() Config {
		c := DefaultConfig()
		c.MaintenanceInterval = 5 * time.Millisecond
		c.EnableCheckLog = boolPtr(false)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	// The loop is started under a span, the way Forge starts an extension
	// under its boot span. Each run must still start a trace of its own.
	ctx, boot := telemetry.StartSpan(context.Background(), "start warden")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	eng.StartMaintenance(ctx)
	run := waitForSpan(t, ended, "run maintenance")
	cancel()
	boot.End()

	if run.Parent().IsValid() || run.SpanContext().TraceID() == boot.SpanContext().TraceID() {
		t.Error("a scheduled maintenance run joined the boot trace")
	}
	wantAttrs(t, run,
		attribute.String("warden.maintenance.scope", "all"),
		attribute.Int64("warden.maintenance.assignments_purged", 0),
		attribute.Int64("warden.maintenance.checklogs_purged", 0),
	)
}

func TestRunMaintenance_SpansFollowTheCaller(t *testing.T) {
	rec := recordSpans(t)
	ctx := context.Background()
	s := memory.New()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: tracedTenant, RoleID: id.NewRoleID(),
		SubjectKind: "user", SubjectID: tracedSubject, ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })
	eng.nowFn = fakeClock(now)

	ctx, parent := telemetry.StartSpan(ctx, "handle request")
	if _, err := eng.RunTenantMaintenance(ctx, tracedTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RunMaintenance(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RunTenantMaintenance(ctx, ""); err == nil {
		t.Fatal("expected an empty tenant to be refused")
	}
	parent.End()

	var runs []sdktrace.ReadOnlySpan
	for _, sp := range rec.Ended() {
		if sp.Name() == "run maintenance" {
			runs = append(runs, sp)
		}
	}
	if len(runs) != 3 {
		t.Fatalf("got %d maintenance spans, want 3", len(runs))
	}
	for _, sp := range runs {
		if sp.Parent().SpanID() != parent.SpanContext().SpanID() {
			t.Error("a maintenance run called in a request is not a child of its span")
		}
	}
	wantAttrs(t, runs[0], attribute.String("warden.maintenance.scope", "tenant"), attribute.Int64("warden.maintenance.assignments_purged", 1))
	wantAttrs(t, runs[1], attribute.String("warden.maintenance.scope", "all"), attribute.Int64("warden.maintenance.assignments_purged", 0))
	if runs[2].Status().Code != codes.Error || runs[2].Status().Description != "warden.ErrTenantRequired" {
		t.Errorf("refused run status = %+v", runs[2].Status())
	}
	assertNeverRecorded(t, rec.Ended(), tracedSubject, tracedTenant)
}

// spanSeeingStore reports the span context each maintenance purge's ctx
// carries.
type spanSeeingStore struct {
	*memory.Store
	seen chan trace.SpanContext
}

func (s spanSeeingStore) DeleteExpiredAssignments(ctx context.Context, now time.Time) (int64, error) {
	select {
	case s.seen <- trace.SpanContextFromContext(ctx):
	default:
	}
	return s.Store.DeleteExpiredAssignments(ctx, now)
}

// TestStartMaintenance_LoopDropsTheCallersSpan: StartMaintenance is often
// handed a ctx with a span on it (Forge starts extensions under a boot
// span), and the loop outlives that span. Its queries must never see it.
func TestStartMaintenance_LoopDropsTheCallersSpan(t *testing.T) {
	newEngine := func(t *testing.T) (*Engine, chan trace.SpanContext) {
		t.Helper()
		seen := make(chan trace.SpanContext, 1)
		eng, err := NewEngine(WithStore(spanSeeingStore{Store: memory.New(), seen: seen}), WithConfig(func() Config {
			c := DefaultConfig()
			c.MaintenanceInterval = 5 * time.Millisecond
			c.EnableCheckLog = boolPtr(false)
			return c
		}()))
		if err != nil {
			t.Fatal(err)
		}
		return eng, seen
	}
	next := func(t *testing.T, seen chan trace.SpanContext) trace.SpanContext {
		t.Helper()
		select {
		case sc := <-seen:
			return sc
		case <-time.After(5 * time.Second):
			t.Fatal("the maintenance loop never ran")
			return trace.SpanContext{}
		}
	}

	// With no SDK installed, starting a span hands the parent straight
	// back, new root or not, so only stripping it keeps it out.
	t.Run("no tracer provider", func(t *testing.T) {
		prev := otel.GetTracerProvider()
		otel.SetTracerProvider(noop.NewTracerProvider())
		t.Cleanup(func() { otel.SetTracerProvider(prev) })

		boot := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled,
		})
		ctx, cancel := context.WithCancel(trace.ContextWithSpanContext(context.Background(), boot))
		defer cancel()
		eng, seen := newEngine(t)
		eng.StartMaintenance(ctx)
		if sc := next(t, seen); sc.IsValid() {
			t.Errorf("a maintenance query ran under span %s of the caller's trace", sc.SpanID())
		}
	})

	t.Run("sdk tracer provider", func(t *testing.T) {
		recordSpans(t)
		ctx, boot := telemetry.StartSpan(context.Background(), "start warden")
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		eng, seen := newEngine(t)
		eng.StartMaintenance(ctx)
		boot.End()
		sc := next(t, seen)
		if sc.TraceID() == boot.SpanContext().TraceID() {
			t.Error("a maintenance query ran in the boot trace")
		}
		if !sc.IsValid() {
			t.Error("a maintenance query ran outside its run's span")
		}
	})
}

func TestSpanName_OnlyLetsSchemaNamesThrough(t *testing.T) {
	for in, want := range map[string]string{
		"read":                   "read",
		"document:read":          "document:read",
		"billing/invoice.v2-x_*": "billing/invoice.v2-x_*",
		strings.Repeat("a", 64):  strings.Repeat("a", 64),
		strings.Repeat("a", 65):  "invalid",
		"":                       "invalid",
		"alice@example.com":      "invalid",
		"read docs":              "invalid",
		"réad":                   "invalid",
	} {
		if got := spanName(in); got != want {
			t.Errorf("spanName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCheck_CallerSuppliedNamesAreCheckedBeforeTheyReachASpan: the HTTP
// check routes pass the action and resource type through as sent, so a
// caller can put an email or a huge string in either.
func TestCheck_CallerSuppliedNamesAreCheckedBeforeTheyReachASpan(t *testing.T) {
	rec := recordSpans(t)
	eng, err := NewEngine(WithStore(memory.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	huge := strings.Repeat("x", 10*1024)
	for _, req := range []*CheckRequest{
		{Subject: Subject{Kind: SubjectUser, ID: "u1"}, Action: Action{Name: tracedSubject}, Resource: Resource{Type: "doc", ID: "d1"}, TenantID: "t1"},
		{Subject: Subject{Kind: SubjectUser, ID: "u1"}, Action: Action{Name: huge}, Resource: Resource{Type: huge, ID: "d1"}, TenantID: "t1"},
	} {
		if _, err := eng.Check(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}

	var checks int
	for _, s := range rec.Ended() {
		if s.Name() != "check permission" {
			continue
		}
		checks++
		if got := spanAttrs(s)["warden.action"].AsString(); got != "invalid" {
			t.Errorf("warden.action = %.40q, want invalid", got)
		}
	}
	if checks != 2 {
		t.Fatalf("got %d check spans, want 2", checks)
	}
	assertNeverRecorded(t, rec.Ended(), tracedSubject, huge[:65])
}

// countingProvider counts the spans started through it, sampled or not.
type countingProvider struct {
	noop.TracerProvider
	tp      trace.TracerProvider
	mu      sync.Mutex
	started []string
}

func (p *countingProvider) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	return countingTracer{Tracer: p.tp.Tracer(name, opts...), p: p}
}

func (p *countingProvider) names() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.started...)
}

type countingTracer struct {
	trace.Tracer
	p *countingProvider
}

func (t countingTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	t.p.mu.Lock()
	t.p.started = append(t.p.started, name)
	t.p.mu.Unlock()
	return t.Tracer.Start(ctx, name, opts...)
}

// TestCheck_UnsampledCheckStartsNoChildSpans: an unsampled check pays for
// its own span and nothing under it.
func TestCheck_UnsampledCheckStartsNoChildSpans(t *testing.T) {
	for name, tc := range map[string]struct {
		sampler sdktrace.Sampler
		want    string
	}{
		"unsampled": {sdktrace.NeverSample(), "check permission"},
		"sampled":   {sdktrace.AlwaysSample(), "check permission,evaluate rbac,evaluate rebac,walk relation graph,evaluate abac"},
	} {
		t.Run(name, func(t *testing.T) {
			sdk := sdktrace.NewTracerProvider(sdktrace.WithSampler(tc.sampler))
			counter := &countingProvider{tp: sdk}
			prev := otel.GetTracerProvider()
			otel.SetTracerProvider(counter)
			t.Cleanup(func() {
				otel.SetTracerProvider(prev)
				_ = sdk.Shutdown(context.Background())
			})

			s := memory.New()
			if err := s.CreatePolicy(context.Background(), &policy.Policy{
				TenantID: tracedTenant, Name: "read-docs", Effect: policy.EffectAllow, IsActive: true,
				Actions: []string{"read"}, Resources: []string{"doc:*"},
			}); err != nil {
				t.Fatal(err)
			}
			eng, err := NewEngine(WithStore(s), WithConfig(func() Config {
				c := DefaultConfig()
				c.EnableCheckLog = boolPtr(false)
				return c
			}()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = eng.Stop(context.Background()) })

			if _, err := eng.Check(context.Background(), tracedRequest()); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(counter.names(), ","); got != tc.want {
				t.Errorf("spans started: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// BenchmarkCheckTracing is BenchmarkCheckWithNamespace at depth 0 (an RBAC
// allow, then ABAC) under no SDK, an SDK that samples nothing, and one that
// samples everything with no exporter.
func BenchmarkCheckTracing(b *testing.B) {
	for name, tp := range map[string]trace.TracerProvider{
		"no_sdk":        noop.NewTracerProvider(),
		"sdk_unsampled": sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample())),
		"sdk_sampled":   sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample())),
	} {
		b.Run(name, func(b *testing.B) {
			prev := otel.GetTracerProvider()
			otel.SetTracerProvider(tp)
			b.Cleanup(func() { otel.SetTracerProvider(prev) })

			ctx := WithTenant(context.Background(), "app1", "t1")
			s := memory.New()
			eng, err := NewEngine(WithStore(s))
			if err != nil {
				b.Fatal(err)
			}
			roleID := id.NewRoleID()
			_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "viewer", Slug: "viewer"})
			_ = s.CreatePermission(ctx, &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"})
			_ = s.AttachPermission(ctx, "t1", roleID, permission.Ref{Name: "doc:read"})
			_ = s.CreateAssignment(ctx, &assignment.Assignment{
				ID: id.NewAssignmentID(), TenantID: "t1", RoleID: roleID, SubjectKind: "user", SubjectID: "u1",
			})
			req := &CheckRequest{Subject: Subject{Kind: SubjectUser, ID: "u1"}, Action: Action{Name: "read"}, Resource: Resource{Type: "doc", ID: "d1"}}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if res, err := eng.Check(ctx, req); err != nil || !res.Allowed {
					b.Fatalf("check = %+v, %v", res, err)
				}
			}
		})
	}
}
