package extension

import (
	"strings"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/warden/store/memory"
)

// newTestApp builds a minimal forge.App the way a real host application
// would, with no config files on disk to discover, so Register runs
// against forge's real Register/init path rather than a stand-in.
func newTestApp(name string) forge.App {
	return forge.New(forge.WithAppName(name))
}

// TestRegister_RefusesUnauthenticatedRoutesWithoutInsecureOption exercises
// the real C1 gate directly through Extension.Register (not a copy of its
// logic): routes enabled plus Auth.RequireIdentity=false, with no
// WithInsecureAllowUnauthenticatedRoutes(), must refuse to start rather
// than silently mount an unauthenticated management API.
func TestRegister_RefusesUnauthenticatedRoutesWithoutInsecureOption(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			Auth: AuthConfig{RequireIdentity: false, AuditLog: true},
		}),
	)

	err := ext.Register(newTestApp("gate-a"))
	if err == nil {
		t.Fatal("Register succeeded with routes enabled and RequireIdentity=false and no insecure opt-in; want an error")
	}
	if !strings.Contains(err.Error(), "WithInsecureAllowUnauthenticatedRoutes") {
		t.Fatalf("error does not name the escape hatch option: %v", err)
	}
}

// TestRegister_SucceedsWithInsecureOption is the same configuration as
// above, but with the explicit opt-in: Register must succeed.
func TestRegister_SucceedsWithInsecureOption(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			Auth: AuthConfig{RequireIdentity: false, AuditLog: true},
		}),
		WithInsecureAllowUnauthenticatedRoutes(),
	)

	if err := ext.Register(newTestApp("gate-b")); err != nil {
		t.Fatalf("Register failed with the insecure opt-in set: %v", err)
	}
	if ext.Engine() == nil {
		t.Fatal("Register succeeded but did not construct an engine")
	}
}

// TestRegister_SucceedsWithRequireIdentityFalseWhenRoutesDisabled proves
// the gate is specifically about routes being reachable, not about the
// RequireIdentity value in isolation: with DisableRoutes=true nothing is
// exposed over HTTP, so RequireIdentity=false needs no escape hatch.
func TestRegister_SucceedsWithRequireIdentityFalseWhenRoutesDisabled(t *testing.T) {
	ext := New(
		WithStore(memory.New()),
		WithConfig(Config{
			Auth: AuthConfig{RequireIdentity: false, AuditLog: true},
		}),
		WithDisableRoutes(),
	)

	if err := ext.Register(newTestApp("gate-c")); err != nil {
		t.Fatalf("Register failed with DisableRoutes=true and no insecure opt-in: %v", err)
	}
	if ext.Engine() == nil {
		t.Fatal("Register succeeded but did not construct an engine")
	}
}

// TestRegister_SecureDefaultsNeedNoOptIn is the control case: the
// defaults (RequireIdentity=true) never need the insecure escape hatch,
// with or without routes enabled.
func TestRegister_SecureDefaultsNeedNoOptIn(t *testing.T) {
	ext := New(WithStore(memory.New()))

	if err := ext.Register(newTestApp("gate-d")); err != nil {
		t.Fatalf("Register failed with secure defaults: %v", err)
	}
}
