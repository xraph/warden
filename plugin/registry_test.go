package plugin

import (
	"context"
	"log/slog"
	"testing"

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
	reg := NewRegistry(slog.Default())

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
