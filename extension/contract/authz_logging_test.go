package contract

import (
	"bytes"
	"context"
	"testing"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

// countCheckLogs stops the engine, which flushes the check log writer, and
// counts the rows tenant t1 holds.
func countCheckLogs(t *testing.T, s *memory.Store, stop func(context.Context) error) int64 {
	t.Helper()
	ctx := context.Background()
	if err := stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	n, err := s.CountCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("count check logs: %v", err)
	}
	return n
}

// TestAuthorizingAQueryWritesNoCheckLog pins that a dashboard read leaves
// the check log alone. Every page view and poll is authorized, so a logged
// read would fill the log an operator browses with the dashboard's own
// traffic. Both an allowed and a denied query are dry runs.
func TestAuthorizingAQueryWritesNoCheckLog(t *testing.T) {
	s := memory.New()
	grantUser(t, s, "reader", "warden:role:read")
	eng := engineOver(t, s)
	a := newEngineAuthorizer(Deps{Engine: eng, DefaultTenantID: "t1"})

	if dec, err := authorize(t, a, userPrincipal("reader"), "roles.list"); err != nil || !dec.Allow {
		t.Fatalf("roles.list for a reader: allow=%v err=%v, want allowed", dec.Allow, err)
	}
	if dec, err := authorize(t, a, userPrincipal("nobody"), "roles.list"); err != nil || dec.Allow {
		t.Fatalf("roles.list for nobody: allow=%v err=%v, want denied", dec.Allow, err)
	}
	if n := countCheckLogs(t, s, eng.Stop); n != 0 {
		t.Fatalf("authorizing two queries left %d check log rows, want 0", n)
	}
}

// TestAuthorizingACommandWritesACheckLog pins the other half: a write is
// rare and is what an auditor looks for, so authorizing one stays a real,
// logged check, allowed or denied.
func TestAuthorizingACommandWritesACheckLog(t *testing.T) {
	s := memory.New()
	grantUser(t, s, "admin", "warden:role:manage")
	eng := engineOver(t, s)
	a := newEngineAuthorizer(Deps{Engine: eng, DefaultTenantID: "t1"})

	if dec, err := authorize(t, a, userPrincipal("admin"), "roles.create"); err != nil || !dec.Allow {
		t.Fatalf("roles.create for an admin: allow=%v err=%v, want allowed", dec.Allow, err)
	}
	if dec, err := authorize(t, a, userPrincipal("nobody"), "roles.create"); err != nil || dec.Allow {
		t.Fatalf("roles.create for nobody: allow=%v err=%v, want denied", dec.Allow, err)
	}
	if n := countCheckLogs(t, s, eng.Stop); n != 2 {
		t.Fatalf("authorizing two commands left %d check log rows, want 2", n)
	}
}

// TestEveryIntentHasAKnownKind pins that the authorizer decides whether to
// log from warden's own manifest, for every intent it gates. The envelope's
// kind comes from the browser, so it is never the input.
func TestEveryIntentHasAKnownKind(t *testing.T) {
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	kinds, err := commandIntents()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range m.Intents {
		want := in.Kind == dashcontract.IntentKindCommand
		if got, ok := kinds[in.Name]; !ok || got != want {
			t.Errorf("%s: logged=%v (known=%v), want logged=%v", in.Name, got, ok, want)
		}
	}
}
