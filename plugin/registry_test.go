package plugin

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

// countingCheckPlugin counts AfterCheck calls; safe for concurrent use.
type countingCheckPlugin struct {
	name  string
	calls atomic.Int64
}

func (c *countingCheckPlugin) Name() string { return c.name }

func (c *countingCheckPlugin) OnAfterCheck(_ context.Context, _, _ any) error {
	c.calls.Add(1)
	return nil
}

// TestRegistryConcurrentRegisterAndEmit pins that Register may run while
// checks are emitting and while the plugin list is read. Engine.Plugins()
// hands the registry to any caller, so nothing stops a Register after the
// engine starts serving. Run with -race: without the registry's lock this
// reports a data race on the hook slices and on the plugin list.
func TestRegistryConcurrentRegisterAndEmit(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry(log.NewNoopLogger())
	first := &countingCheckPlugin{name: "first"}
	reg.Register(first)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := range 200 {
			reg.Register(&countingCheckPlugin{name: fmt.Sprintf("p%d", i)})
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			reg.EmitAfterCheck(ctx, nil, nil)
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			_ = len(reg.Plugins())
			reg.SetMetrics(noopMetricsRecorder{})
		}
	}()
	wg.Wait()

	if got := len(reg.Plugins()); got != 201 {
		t.Fatalf("Plugins() = %d plugins, want 201", got)
	}
	if first.calls.Load() != 200 {
		t.Fatalf("first plugin saw %d AfterCheck calls, want 200", first.calls.Load())
	}
}

// TestRegistryPluginsReturnsCopy pins that the slice Plugins() returns is
// the caller's own: changing it cannot reorder or replace what the
// registry dispatches to.
func TestRegistryPluginsReturnsCopy(t *testing.T) {
	reg := NewRegistry(log.NewNoopLogger())
	reg.Register(&countingCheckPlugin{name: "a"})
	got := reg.Plugins()
	got[0] = &countingCheckPlugin{name: "b"}
	if name := reg.Plugins()[0].Name(); name != "a" {
		t.Fatalf("registry's first plugin is %q after the caller edited its copy, want %q", name, "a")
	}
}
