package dsl

import (
	"context"
	"embed"
	"errors"
	"strings"
	"testing"

	"github.com/xraph/warden/role"
)

// embedTestFS bundles the dsl/testdata/embed/ tree directly into the
// test binary so the //go:embed path is exercised end-to-end with no
// filesystem dependency at test time.
//
// `all:` prefix is required because the tree contains a `_shared/`
// directory — Go's default //go:embed pattern strips leading-underscore
// directories, but Warden's convention keeps them.
//
//go:embed all:testdata/embed
var embedTestFS embed.FS

func TestApplyFS_FromEmbed(t *testing.T) {
	ctx := context.Background()
	eng, store := newTestEngine(t)

	res, err := ApplyFS(ctx, eng, embedTestFS, "testdata/embed",
		ApplyOptions{TenantID: "t-acme"},
		WithVariables(Variables{
			"TENANT": "t-acme",
			"REGION": "us-east-1",
		}),
	)
	if err != nil {
		t.Fatalf("ApplyFS: %v", err)
	}
	if len(res.Created) == 0 {
		t.Fatalf("expected entries created on first apply, got %+v", res)
	}

	// Verify the role made it through with the substituted name.
	r, err := store.GetRoleBySlug(ctx, "t-acme", "", "viewer")
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}
	if r.Name != "Viewer (us-east-1)" {
		t.Errorf("role.Name = %q, want %q", r.Name, "Viewer (us-east-1)")
	}

	// Idempotency: second apply produces no Created/Updated/Deleted.
	res2, err := ApplyFS(ctx, eng, embedTestFS, "testdata/embed",
		ApplyOptions{TenantID: "t-acme"},
		WithVariables(Variables{
			"TENANT": "t-acme",
			"REGION": "us-east-1",
		}),
	)
	if err != nil {
		t.Fatalf("second ApplyFS: %v", err)
	}
	if len(res2.Created)+len(res2.Updated)+len(res2.Deleted) != 0 {
		t.Errorf("second apply should be a no-op, got %+v", res2)
	}
	if res2.NoOps == 0 {
		t.Errorf("second apply should report NoOps > 0, got %d", res2.NoOps)
	}
}

func TestApplyFS_MissingVariableReturnsDiagnosticError(t *testing.T) {
	ctx := context.Background()
	eng, _ := newTestEngine(t)

	// Note: only TENANT supplied — REGION is missing, so the role's
	// `name = "Viewer (${REGION})"` substitution should produce a
	// parse-time diagnostic that ApplyFS bubbles up via DiagnosticError.
	_, err := ApplyFS(ctx, eng, embedTestFS, "testdata/embed",
		ApplyOptions{TenantID: "t-acme"},
		WithVariables(Variables{"TENANT": "t-acme"}),
	)
	if err == nil {
		t.Fatal("expected error from missing variable")
	}
	var derr *DiagnosticError
	if !errors.As(err, &derr) {
		t.Fatalf("expected *DiagnosticError, got %T: %v", err, err)
	}
	if len(derr.Diagnostics()) == 0 {
		t.Fatal("DiagnosticError carries no diagnostics")
	}
	saw := false
	for _, d := range derr.Diagnostics() {
		if strings.Contains(d.Msg, "REGION") {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("expected diag mentioning REGION, got: %v", derr.Diagnostics())
	}
}

func TestApplyFile_RoundTrip(t *testing.T) {
	// Cover ApplyFile with a single fixture exercising idempotency.
	ctx := context.Background()
	eng, _ := newTestEngine(t)

	tmp := t.TempDir() + "/onefile.warden"
	src := `warden config 1
tenant t-onefile

permission "doc:read" (document : read)

role viewer {
  name   = "Viewer"
  grants = ["doc:read"]
}
`
	if err := writeTestFile(tmp, src); err != nil {
		t.Fatal(err)
	}

	res, err := ApplyFile(ctx, eng, tmp, ApplyOptions{TenantID: "t-onefile"})
	if err != nil {
		t.Fatalf("ApplyFile: %v", err)
	}
	if len(res.Created) == 0 {
		t.Fatal("expected creations on first apply")
	}
	res2, err := ApplyFile(ctx, eng, tmp, ApplyOptions{TenantID: "t-onefile"})
	if err != nil {
		t.Fatalf("second ApplyFile: %v", err)
	}
	if len(res2.Created)+len(res2.Updated)+len(res2.Deleted) != 0 {
		t.Errorf("second apply should be a no-op, got %+v", res2)
	}
}

func TestApplyDir_RoundTrip(t *testing.T) {
	ctx := context.Background()
	eng, _ := newTestEngine(t)

	dir := t.TempDir()
	if err := writeTestFile(dir+"/main.warden", `warden config 1
tenant t-dir

permission "doc:read" (document : read)

role viewer {
  grants = ["doc:read"]
}
`); err != nil {
		t.Fatal(err)
	}

	_, err := ApplyDir(ctx, eng, dir, ApplyOptions{TenantID: "t-dir"})
	if err != nil {
		t.Fatalf("ApplyDir: %v", err)
	}

	// Verify a role landed in the store.
	roles, err := eng.Store().ListRoles(ctx, &role.ListFilter{TenantID: "t-dir"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range roles {
		if r.Slug == "viewer" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("role 'viewer' not found after ApplyDir")
	}
}

func TestDiagnosticError_ErrorsAs(t *testing.T) {
	// Use Apply directly with a Program that has resolver errors —
	// referencing an undeclared parent role triggers a diagnostic.
	ctx := context.Background()
	eng, _ := newTestEngine(t)

	src := []byte(`warden config 1
tenant t-bad

role child : ghost {
  name = "Child"
}
`)
	prog, parseErrs := Parse("bad.warden", src)
	if len(parseErrs) > 0 {
		t.Fatalf("setup: parse errors %v", parseErrs)
	}
	_, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t-bad"})
	if err == nil {
		t.Fatal("expected resolver error")
	}
	var derr *DiagnosticError
	if !errors.As(err, &derr) {
		t.Fatalf("expected *DiagnosticError, got %T: %v", err, err)
	}
	if len(derr.Diagnostics()) == 0 {
		t.Fatal("expected at least one diagnostic")
	}
	saw := false
	for _, d := range derr.Diagnostics() {
		if strings.Contains(d.Msg, "ghost") {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("expected 'ghost' in diag, got: %v", derr.Diagnostics())
	}
}
