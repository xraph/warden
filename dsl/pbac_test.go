package dsl

import (
	"strings"
	"testing"
	"time"
)

// TestParser_PolicyPBAC asserts the parser captures PBAC fields
// (not_before, not_after, obligations) on PolicyDecl with correct types.
func TestParser_PolicyPBAC(t *testing.T) {
	src := `
warden config 1

policy "incident-freeze" {
    effect      = deny
    priority    = 1
    active      = true
    not_after   = "2026-06-01T00:00:00Z"
    actions     = ["deploy:*"]
    obligations = ["notify-oncall", "audit-log"]
}

policy "q2-window" {
    effect      = allow
    priority    = 100
    active      = true
    not_before  = "2026-04-01T00:00:00Z"
    not_after   = "2026-07-01T00:00:00Z"
    actions     = ["export"]
    obligations = ["audit-log"]
}
`
	prog := mustParse(t, src)
	if len(prog.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(prog.Policies))
	}

	freeze := prog.Policies[0]
	if freeze.Name != "incident-freeze" {
		t.Fatalf("policy[0].Name = %q", freeze.Name)
	}
	if freeze.NotBefore != nil {
		t.Errorf("incident-freeze should have no not_before")
	}
	if freeze.NotAfter == nil {
		t.Fatal("incident-freeze should have not_after")
	}
	want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if !freeze.NotAfter.Equal(want) {
		t.Errorf("not_after = %v, want %v", freeze.NotAfter, want)
	}
	if got := strings.Join(freeze.Obligations, ","); got != "notify-oncall,audit-log" {
		t.Errorf("obligations = %q", got)
	}

	q2 := prog.Policies[1]
	if q2.NotBefore == nil || q2.NotAfter == nil {
		t.Fatal("q2-window should have both bounds")
	}
}

// TestParser_PolicyPBAC_InvalidTimestamp asserts that a malformed
// not_before / not_after produces a diagnostic, not a panic.
func TestParser_PolicyPBAC_InvalidTimestamp(t *testing.T) {
	src := `
warden config 1

policy "broken" {
    effect    = allow
    not_after = "not a real timestamp"
}
`
	_, diags := Parse("test.warden", []byte(src))
	if len(diags) == 0 {
		t.Fatal("expected diagnostic for invalid timestamp")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Msg, "RFC3339") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RFC3339 diag, got: %v", diags)
	}
}

// TestResolver_PolicyPBAC_NotAfterBeforeNotBefore asserts the resolver
// flags windows where the upper bound predates the lower bound.
func TestResolver_PolicyPBAC_NotAfterBeforeNotBefore(t *testing.T) {
	src := `
warden config 1

policy "inverted" {
    effect     = allow
    not_before = "2027-01-01T00:00:00Z"
    not_after  = "2026-01-01T00:00:00Z"
}
`
	prog := mustParse(t, src)
	diags := Resolve(prog)
	found := false
	for _, d := range diags {
		if strings.Contains(d.Msg, "not_after") && strings.Contains(d.Msg, "not_before") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected resolver diagnostic about inverted window, got: %v", diags)
	}
}

// TestFormat_PolicyPBAC asserts the formatter emits the new fields in
// the canonical position and is round-trip stable.
func TestFormat_PolicyPBAC(t *testing.T) {
	src := `warden config 1

policy "scheduled-grant" {
    effect      = allow
    priority    = 100
    active      = true
    not_before  = "2026-04-01T00:00:00Z"
    not_after   = "2026-07-01T00:00:00Z"
    obligations = ["audit-log", "notify-security"]
    actions     = ["export"]
}
`
	prog := mustParse(t, src)
	out := Format(prog)
	for _, want := range []string{
		`not_before = "2026-04-01T00:00:00Z"`,
		`not_after = "2026-07-01T00:00:00Z"`,
		`obligations = [`,
		`"audit-log"`,
		`"notify-security"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("formatted output missing %q\n----\n%s", want, out)
		}
	}

	// Round-trip stability.
	prog2, diags := Parse("fmt.warden", []byte(out))
	if len(diags) > 0 {
		t.Fatalf("re-parse diags: %v", diags)
	}
	out2 := Format(prog2)
	if out != out2 {
		t.Errorf("formatter is not idempotent\nfirst:\n%s\nsecond:\n%s", out, out2)
	}
}
