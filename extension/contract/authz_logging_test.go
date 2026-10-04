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

// TestEveryGatedIntentHasAKind pins that every intent Authorize has a policy
// for also has a kind in the manifest, since Authorize denies an intent it
// cannot find a kind for. The envelope's kind comes from the browser, so it
// is never the input.
func TestEveryGatedIntentHasAKind(t *testing.T) {
	kinds, err := commandIntents()
	if err != nil {
		t.Fatal(err)
	}
	for intent := range intentPolicies {
		if _, ok := kinds[intent]; !ok {
			t.Errorf("%s has an authorization policy but no kind in manifest.yaml", intent)
		}
	}
}

// TestHandlerGrantChecksLogLikeTheirIntent pins the flags the handlers pass
// to principalHolds by hand: subjects.detail, schema.export and schema.plan
// are queries and dry-run their extra grant checks; schema.apply is a
// command and logs them.
func TestHandlerGrantChecksLogLikeTheirIntent(t *testing.T) {
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	passed := map[string]bool{
		"subjects.detail": false,
		"schema.export":   false,
		"schema.plan":     false,
		"schema.apply":    true,
	}
	for _, in := range m.Intents {
		logged, ok := passed[in.Name]
		if !ok {
			continue
		}
		if want := in.Kind == dashcontract.IntentKindCommand; logged != want {
			t.Errorf("%s passes logged=%v to principalHolds, but its kind is %s", in.Name, logged, in.Kind)
		}
	}
}
