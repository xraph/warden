package auditlog

import (
	"context"
	"testing"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden"
	"github.com/xraph/warden/plugin"
)

// fakeLogger captures the last Info() call. It embeds a nil log.Logger to
// satisfy the rest of the interface: OnAudit only ever calls Info, so the
// unimplemented methods are never reached.
type fakeLogger struct {
	log.Logger
	msg    string
	fields []log.Field
	calls  int
}

func (f *fakeLogger) Info(msg string, fields ...log.Field) {
	f.msg = msg
	f.fields = fields
	f.calls++
}

func fieldMap(fields []log.Field) map[string]any {
	m := make(map[string]any, len(fields))
	for _, fl := range fields {
		m[fl.Key()] = fl.Value()
	}
	return m
}

func TestNew_NilLoggerFallsBackToNoop(t *testing.T) {
	p := New(nil)
	// Must not panic writing through the no-op fallback.
	if err := p.OnAudit(context.Background(), plugin.Event{Action: "role.created"}); err != nil {
		t.Fatalf("OnAudit with a nil logger returned an error: %v", err)
	}
}

func TestName(t *testing.T) {
	p := New(nil)
	if p.Name() != "auditlog" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "auditlog")
	}
}

func TestOnAudit_LogsOneStructuredLine(t *testing.T) {
	fl := &fakeLogger{}
	p := New(fl)

	at := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	actor := warden.Actor{Kind: "user", ID: "alice", Via: "forge"}
	entity := map[string]string{"name": "editor"}

	err := p.OnAudit(context.Background(), plugin.Event{
		Actor:    actor,
		At:       at,
		Action:   "role.created",
		TenantID: "t1",
		EntityID: "role_123",
		Entity:   entity,
	})
	if err != nil {
		t.Fatalf("OnAudit returned an error: %v", err)
	}
	if fl.calls != 1 {
		t.Fatalf("Info called %d times, want exactly 1 (one structured line per audit event)", fl.calls)
	}
	if fl.msg != "warden: audit" {
		t.Fatalf("log message = %q, want %q", fl.msg, "warden: audit")
	}

	got := fieldMap(fl.fields)
	if got["action"] != "role.created" {
		t.Errorf("action field = %v, want %q", got["action"], "role.created")
	}
	if got["tenant_id"] != "t1" {
		t.Errorf("tenant_id field = %v, want %q", got["tenant_id"], "t1")
	}
	if got["entity_id"] != "role_123" {
		t.Errorf("entity_id field = %v, want %q", got["entity_id"], "role_123")
	}
	if got["actor_kind"] != "user" || got["actor_id"] != "alice" || got["actor_via"] != "forge" {
		t.Errorf("actor fields not decomposed from warden.Actor: %+v", got)
	}
	if _, ok := got["entity"]; !ok {
		t.Error("entity field missing")
	}
	if _, ok := got["before"]; ok {
		t.Error("before field present for a create event that had none")
	}
}

func TestOnAudit_IncludesBeforeOnUpdate(t *testing.T) {
	fl := &fakeLogger{}
	p := New(fl)

	err := p.OnAudit(context.Background(), plugin.Event{
		Action: "role.updated",
		Entity: map[string]string{"name": "new"},
		Before: map[string]string{"name": "old"},
	})
	if err != nil {
		t.Fatalf("OnAudit returned an error: %v", err)
	}
	got := fieldMap(fl.fields)
	if _, ok := got["before"]; !ok {
		t.Error("before field missing for an update event")
	}
}

func TestOnAudit_HandlesNonWardenActorGracefully(t *testing.T) {
	fl := &fakeLogger{}
	p := New(fl)

	// Actor is `any` in plugin.Event; a caller that isn't warden itself
	// (a test, or a future non-Go caller marshaling raw JSON) might not
	// send a warden.Actor. OnAudit must not panic on that.
	err := p.OnAudit(context.Background(), plugin.Event{
		Action: "role.created",
		Actor:  "not-a-warden-actor",
	})
	if err != nil {
		t.Fatalf("OnAudit returned an error: %v", err)
	}
	got := fieldMap(fl.fields)
	if got["actor"] != "not-a-warden-actor" {
		t.Errorf("actor field = %v, want the raw fallback value", got["actor"])
	}
}

func TestOnAudit_RequestAndTraceIDsOptional(t *testing.T) {
	fl := &fakeLogger{}
	p := New(fl)

	if err := p.OnAudit(context.Background(), plugin.Event{
		Action:    "role.created",
		RequestID: "req-1",
		TraceID:   "trace-1",
	}); err != nil {
		t.Fatalf("OnAudit returned an error: %v", err)
	}
	got := fieldMap(fl.fields)
	if got["request_id"] != "req-1" || got["trace_id"] != "trace-1" {
		t.Errorf("request/trace id fields missing: %+v", got)
	}
}
