package dsl

import (
	"os"
	"strings"
	"testing"
)

func TestSubstituteVariables_Basic(t *testing.T) {
	src := []byte(`warden config 1
tenant ${TENANT}
role ${SLUG_DOES_NOT_EXIST_HERE} {
}`)
	out, diags := SubstituteVariables("test.warden", src, Variables{
		"TENANT": "acme",
	})
	got := string(out)
	if !strings.Contains(got, "tenant acme") {
		t.Errorf("expected `tenant acme` in output, got: %s", got)
	}
	// Missing variable should produce a diagnostic but leave the placeholder.
	if len(diags) != 1 {
		t.Fatalf("expected exactly 1 diagnostic for the missing var, got %d", len(diags))
	}
	if !strings.Contains(diags[0].Msg, "SLUG_DOES_NOT_EXIST_HERE") {
		t.Errorf("diag should name the missing var, got: %s", diags[0].Msg)
	}
}

func TestSubstituteVariables_InString(t *testing.T) {
	src := []byte(`warden config 1
policy "p" {
  description = "Built for ${ENV}"
}`)
	out, diags := SubstituteVariables("t", src, Variables{"ENV": "production"})
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if !strings.Contains(string(out), `"Built for production"`) {
		t.Errorf("string interpolation failed: %s", out)
	}
}

func TestSubstituteVariables_DollarEscape(t *testing.T) {
	// `$$` should produce a literal `$` and not start substitution.
	// `$${VAR}` therefore yields `${VAR}` verbatim.
	src := []byte(`role x {
  description = "use $${TENANT} to inject the tenant id"
}`)
	out, diags := SubstituteVariables("t", src, Variables{"TENANT": "acme"})
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if !strings.Contains(string(out), `"use ${TENANT} to inject the tenant id"`) {
		t.Errorf("$$ escape failed: %s", out)
	}
	if strings.Contains(string(out), "acme") {
		t.Errorf("substitution should have been escaped, got: %s", out)
	}
}

func TestSubstituteVariables_UnclosedBrace(t *testing.T) {
	src := []byte("tenant ${UNCLOSED\nrole x {}\n")
	_, diags := SubstituteVariables("t", src, Variables{"UNCLOSED": "x"})
	if len(diags) == 0 {
		t.Fatal("expected unclosed-brace diagnostic")
	}
	if !strings.Contains(diags[0].Msg, "unclosed") {
		t.Errorf("expected 'unclosed' in diag, got: %s", diags[0].Msg)
	}
}

func TestSubstituteVariables_InvalidName(t *testing.T) {
	src := []byte(`tenant ${1BAD}` + "\n")
	_, diags := SubstituteVariables("t", src, Variables{"1BAD": "x"})
	if len(diags) == 0 {
		t.Fatal("expected invalid-name diagnostic")
	}
	if !strings.Contains(diags[0].Msg, "invalid variable name") {
		t.Errorf("expected 'invalid variable name', got: %s", diags[0].Msg)
	}
}

func TestSubstituteVariables_Position(t *testing.T) {
	// Diagnostic position must point at the placeholder, not the variable
	// value or the substituted region.
	src := []byte(`warden config 1
tenant ${MISSING}
`)
	_, diags := SubstituteVariables("t.warden", src, Variables{})
	if len(diags) != 1 {
		t.Fatalf("expected 1 diag, got %d", len(diags))
	}
	if diags[0].Pos.Line != 2 {
		t.Errorf("diag.Pos.Line = %d, want 2", diags[0].Pos.Line)
	}
	if diags[0].Pos.Col != 8 {
		t.Errorf("diag.Pos.Col = %d, want 8 (column of `$`)", diags[0].Pos.Col)
	}
}

func TestLoadFile_WithVariables(t *testing.T) {
	// End-to-end: source uses ${TENANT}, loader substitutes, parser sees
	// the final value, no diagnostics.
	tmp := t.TempDir()
	path := tmp + "/v.warden"
	if err := writeTestFile(path, `warden config 1
tenant ${TENANT}

role admin {
  name = "Admin (${TENANT})"
}
`); err != nil {
		t.Fatal(err)
	}
	prog, errs, err := LoadFile(path, WithVariables(Variables{"TENANT": "acme"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected diagnostics: %v", errs)
	}
	if prog.Tenant != "acme" {
		t.Errorf("Tenant = %q, want %q", prog.Tenant, "acme")
	}
	if len(prog.Roles) != 1 || prog.Roles[0].Name != "Admin (acme)" {
		t.Errorf("role.Name = %q, want %q", prog.Roles[0].Name, "Admin (acme)")
	}
}

func TestEnvVariables(t *testing.T) {
	t.Setenv("WARDEN_VAR_TENANT", "from-env")
	t.Setenv("WARDEN_VAR_REGION", "us-east-1")
	t.Setenv("WARDEN_VAR_INVALID-NAME", "ignored")
	t.Setenv("UNRELATED_VAR", "nope")

	got := EnvVariables()
	if got["TENANT"] != "from-env" {
		t.Errorf("TENANT = %q, want %q", got["TENANT"], "from-env")
	}
	if got["REGION"] != "us-east-1" {
		t.Errorf("REGION = %q", got["REGION"])
	}
	if _, ok := got["INVALID-NAME"]; ok {
		t.Errorf("invalid name should be ignored")
	}
	if _, ok := got["UNRELATED_VAR"]; ok {
		t.Errorf("non-prefixed var should not appear")
	}
}

func TestMergeVariables_OrderWins(t *testing.T) {
	merged := MergeVariables(
		Variables{"A": "from-default", "B": "from-default"},
		Variables{"A": "from-env"},
		Variables{"A": "from-cli"},
	)
	if merged["A"] != "from-cli" {
		t.Errorf("A = %q, want from-cli (last layer wins)", merged["A"])
	}
	if merged["B"] != "from-default" {
		t.Errorf("B = %q, want from-default", merged["B"])
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
