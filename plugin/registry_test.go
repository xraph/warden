package plugin

import (
	"context"
	"errors"
	"testing"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
)

// testPlugin implements Plugin + RoleCreated + AfterCheck.
type testPlugin struct {
	roleCreatedCalled bool
	afterCheckCalled  bool
}

func (t *testPlugin) Name() string { return "test-plugin" }

func (t *testPlugin) OnRoleCreated(_ context.Context, _ *role.Role) error {
	t.roleCreatedCalled = true
	return nil
}

func (t *testPlugin) OnAfterCheck(_ context.Context, _, _ any) error {
	t.afterCheckCalled = true
	return nil
}

// minimalPlugin only implements Plugin (no hooks).
type minimalPlugin struct{}

func (m *minimalPlugin) Name() string { return "minimal" }

func TestRegistryDispatch(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry(log.NewNoopLogger())

	tp := &testPlugin{}
	reg.Register(tp)
	reg.Register(&minimalPlugin{})

	if len(reg.Plugins()) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(reg.Plugins()))
	}

	// Should dispatch RoleCreated to testPlugin only.
	reg.EmitRoleCreated(ctx, &role.Role{ID: id.NewRoleID(), Name: "admin"})
	if !tp.roleCreatedCalled {
		t.Fatal("OnRoleCreated was not called")
	}

	// Should dispatch AfterCheck.
	reg.EmitAfterCheck(ctx, nil, nil)
	if !tp.afterCheckCalled {
		t.Fatal("OnAfterCheck was not called")
	}

	// Should not panic on hooks with no listeners.
	reg.EmitBeforeCheck(ctx, nil)
	reg.EmitRoleDeleted(ctx, id.NewRoleID())
	reg.EmitShutdown(ctx)
}

// panicPlugin panics from every hook it implements, to exercise the
// registry's per-hook panic recovery.
type panicPlugin struct{}

func (p *panicPlugin) Name() string { return "panic-plugin" }
func (p *panicPlugin) OnRoleCreated(_ context.Context, _ *role.Role) error {
	panic("boom")
}

// errPlugin always returns an error from OnRoleCreated.
type errPlugin struct{}

func (p *errPlugin) Name() string { return "err-plugin" }
func (p *errPlugin) OnRoleCreated(_ context.Context, _ *role.Role) error {
	return errors.New("role created failed")
}

type fakeMetrics struct {
	hookErrors []string // "hook/plugin"
}

func (f *fakeMetrics) HookError(hook, plugin string) {
	f.hookErrors = append(f.hookErrors, hook+"/"+plugin)
}

func TestRegistry_PanicRecovery(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry(log.NewNoopLogger())
	metrics := &fakeMetrics{}
	reg.SetMetrics(metrics)

	reg.Register(&panicPlugin{})
	tp := &testPlugin{}
	reg.Register(tp)

	// Must not panic across the whole call, and the second plugin must
	// still run despite the first one panicking.
	reg.EmitRoleCreated(ctx, &role.Role{ID: id.NewRoleID(), Name: "admin"})

	if !tp.roleCreatedCalled {
		t.Fatal("plugin after the panicking one should still be dispatched")
	}
	if len(metrics.hookErrors) != 1 || metrics.hookErrors[0] != "OnRoleCreated/panic-plugin" {
		t.Fatalf("expected one HookError for the panicking plugin, got %v", metrics.hookErrors)
	}
}

func TestRegistry_HookErrorCountsOnReturnedError(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry(log.NewNoopLogger())
	metrics := &fakeMetrics{}
	reg.SetMetrics(metrics)

	reg.Register(&errPlugin{})
	reg.EmitRoleCreated(ctx, &role.Role{ID: id.NewRoleID(), Name: "admin"})

	if len(metrics.hookErrors) != 1 || metrics.hookErrors[0] != "OnRoleCreated/err-plugin" {
		t.Fatalf("expected one HookError for the erroring plugin, got %v", metrics.hookErrors)
	}
}

func TestRegistry_ValidateReturnsImplementedHooks(t *testing.T) {
	reg := NewRegistry(log.NewNoopLogger())

	names := reg.Validate(&testPlugin{})
	want := map[string]bool{"RoleCreated": false, "AfterCheck": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("expected Validate to report %q for testPlugin, got %v", n, names)
		}
	}

	if names := reg.Validate(&minimalPlugin{}); len(names) != 0 {
		t.Fatalf("expected minimalPlugin to implement no hooks, got %v", names)
	}
}

// auditPlugin implements only Audit.
type auditPlugin struct {
	events []Event
}

func (a *auditPlugin) Name() string { return "audit-plugin" }
func (a *auditPlugin) OnAudit(_ context.Context, ev Event) error {
	a.events = append(a.events, ev)
	return nil
}

func TestRegistry_EmitAudit(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry(log.NewNoopLogger())
	ap := &auditPlugin{}
	reg.Register(ap)

	reg.EmitAudit(ctx, Event{Action: "role.created", TenantID: "t1", EntityID: "r1"})

	if len(ap.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(ap.events))
	}
	if ap.events[0].Action != "role.created" || ap.events[0].TenantID != "t1" {
		t.Fatalf("unexpected audit event: %+v", ap.events[0])
	}
}
