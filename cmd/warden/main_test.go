package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCLI_Lint runs the binary as a subprocess against the bundled
// multi-file fixture. Skips on non-Unix to keep the test simple.
func TestCLI_Lint(t *testing.T) {
	bin := buildBin(t)

	// Use the multi-file fixture relative to module root.
	root := moduleRoot(t)
	fixture := filepath.Join(root, "dsl", "testdata", "multi-file")
	cmd := exec.CommandContext(context.Background(), bin, "lint", fixture)
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lint exited %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK in output, got: %s", out)
	}
}

func TestCLI_ApplyMemory(t *testing.T) {
	bin := buildBin(t)
	root := moduleRoot(t)
	fixture := filepath.Join(root, "dsl", "testdata", "multi-file")
	cmd := exec.CommandContext(context.Background(), bin, "apply", "-f", fixture, "--store", "memory:")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("apply exited %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "applied") {
		t.Errorf("expected 'applied' marker, got: %s", out)
	}
	// Memory store is ephemeral per-process: there's no persistent state to
	// re-check across CLI invocations. The test above proves the binary
	// wired everything together; idempotency is covered by dsl/applier_test.
}

// TestCLI_ApplySQLiteIdempotent runs apply twice against a sqlite file and
// verifies the second run is a no-op (every entity already exists). Acts as
// a regression test for the sqlite time.Time scan fix: without that fix,
// the first apply itself failed.
func TestCLI_ApplySQLiteIdempotent(t *testing.T) {
	bin := buildBin(t)
	root := moduleRoot(t)
	fixture := filepath.Join(root, "dsl", "testdata", "multi-file")
	db := filepath.Join(t.TempDir(), "warden.db")
	dsn := "sqlite:" + db

	for i := 0; i < 2; i++ {
		cmd := exec.CommandContext(context.Background(), bin, "apply", "-f", fixture, "--store", dsn)
		cmd.Dir = root
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("apply iter %d exited %v\nstdout: %s\nstderr: %s",
				i, err, stdout.String(), stderr.String())
		}
		out := stdout.String()
		switch i {
		case 0:
			if !strings.Contains(out, "created") {
				t.Errorf("first apply: expected 'created' in output, got: %s", out)
			}
		case 1:
			if !strings.Contains(out, "unchanged") {
				t.Errorf("second apply: expected 'unchanged' (idempotent), got: %s", out)
			}
		}
	}
}

func TestCLI_LintInvalidExitsNonZero(t *testing.T) {
	bin := buildBin(t)

	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad.warden")
	if err := os.WriteFile(bad, []byte("warden config 1\nrole editor : ghost {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), bin, "lint", bad)
	if err := cmd.Run(); err == nil {
		t.Fatal("expected non-zero exit on lint failure")
	}
}

// A ':' in a permission action is a warning in lint, not a failure: apply
// refuses it unless the store already holds that permission with exactly
// that resource and action, and lint reads no store.
func TestCLI_LintWarnsOnAColonAction(t *testing.T) {
	bin := buildBin(t)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "colon.warden")
	if err := os.WriteFile(src, []byte("warden config 1\npermission \"warden:role:manage\" (\"warden\" : \"role:manage\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), bin, "lint", src)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lint exited %v; a warning must not fail it\nstderr: %s", err, stderr.String())
	}
	want := `warning: ` + src + `:2:1: permission "warden:role:manage" has action "role:manage", which contains ':'; the engine joins resource and action with ':', so apply refuses it unless the store already holds this permission with exactly this resource and action`
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
	if !strings.Contains(stdout.String(), "OK") {
		t.Errorf("stdout = %q, want OK", stdout.String())
	}
}

func TestResolveStoreDSN(t *testing.T) {
	t.Run("flag wins when set", func(t *testing.T) {
		t.Setenv("WARDEN_STORE_DSN", "postgres://env-user:env-pass@env-host/db")
		got := resolveStoreDSN("memory:")
		if got != "memory:" {
			t.Errorf("resolveStoreDSN(%q) = %q, want %q", "memory:", got, "memory:")
		}
	})

	t.Run("falls back to env when flag is empty", func(t *testing.T) {
		t.Setenv("WARDEN_STORE_DSN", "sqlite:/tmp/from-env.db")
		got := resolveStoreDSN("")
		if got != "sqlite:/tmp/from-env.db" {
			t.Errorf("resolveStoreDSN(\"\") = %q, want %q", got, "sqlite:/tmp/from-env.db")
		}
	})

	t.Run("empty when neither is set", func(t *testing.T) {
		t.Setenv("WARDEN_STORE_DSN", "")
		if got := resolveStoreDSN(""); got != "" {
			t.Errorf("resolveStoreDSN(\"\") = %q, want empty", got)
		}
	})
}

func buildBin(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("skipping subprocess CLI test on windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "warden")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "github.com/xraph/warden/cmd/warden")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "go", "env", "GOMOD")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	gomod := strings.TrimSpace(string(out))
	return filepath.Dir(gomod)
}
