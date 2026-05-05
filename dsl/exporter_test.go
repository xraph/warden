package dsl

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"
)

// TestExport_RoundTrip applies a known fixture, exports the resulting state,
// re-applies the export to a fresh store, and asserts zero diff. This is
// the GitOps round-trip property the plan calls out as the primary
// verification for D.1.b.
func TestExport_RoundTrip(t *testing.T) {
	src := `warden config 1
tenant t1

resource document {
    relation owner: user
    relation viewer: user
    permission read = viewer or owner
}

permission "doc:read"  (doc : read)
permission "doc:write" (doc : write)

role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}

role editor : viewer {
    name = "Editor"
    grants += ["doc:write"]
}

policy "biz" {
    effect = allow
    priority = 100
    active = true
    actions = ["read"]
}
`
	prog, errs := Parse("test", []byte(src))
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	// First store: populated by Apply.
	s1 := memory.New()
	eng1, err := warden.NewEngine(warden.WithStore(s1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), eng1, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Export to a temp directory, flat layout.
	dir := t.TempDir()
	count, err := Export(context.Background(), eng1, ExportOptions{
		TenantID:  "t1",
		Layout:    FlatLayout,
		OutputDir: dir,
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if count != 1 {
		t.Errorf("flat layout should write 1 file, got %d", count)
	}

	// Read the export back.
	exported, err := os.ReadFile(filepath.Join(dir, "main.warden"))
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	prog2, errs := Parse("export", exported)
	if len(errs) > 0 {
		t.Fatalf("re-parse export: %v\n--- export:\n%s", errs, exported)
	}

	// Apply the exported program to a fresh store.
	s2 := memory.New()
	eng2, _ := warden.NewEngine(warden.WithStore(s2))
	if _, err := Apply(context.Background(), eng2, prog2, ApplyOptions{}); err != nil {
		t.Fatalf("re-apply export: %v", err)
	}

	// Re-export from s2 and confirm bytes match the first export.
	dir2 := t.TempDir()
	if _, err := Export(context.Background(), eng2, ExportOptions{
		TenantID:  "t1",
		Layout:    FlatLayout,
		OutputDir: dir2,
	}); err != nil {
		t.Fatalf("export2: %v", err)
	}
	exported2, err := os.ReadFile(filepath.Join(dir2, "main.warden"))
	if err != nil {
		t.Fatalf("read export2: %v", err)
	}
	if string(exported) != string(exported2) {
		t.Fatalf("round-trip mismatch:\n--- first:\n%s\n--- second:\n%s", exported, exported2)
	}
}

func TestExport_SectionalLayout(t *testing.T) {
	src := `warden config 1
tenant t1

permission "x:y" (x : y)
role r {
    name = "R"
    grants = ["x:y"]
}
`
	prog, _ := Parse("t", []byte(src))
	s := memory.New()
	eng, _ := warden.NewEngine(warden.WithStore(s))
	_, _ = Apply(context.Background(), eng, prog, ApplyOptions{})

	dir := t.TempDir()
	count, err := Export(context.Background(), eng, ExportOptions{
		TenantID:  "t1",
		Layout:    SectionalLayout,
		OutputDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 sectional files (permissions + roles), got %d", count)
	}
	if _, err := os.Stat(filepath.Join(dir, "10-permissions.warden")); err != nil {
		t.Errorf("missing 10-permissions.warden: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-roles.warden")); err != nil {
		t.Errorf("missing 20-roles.warden: %v", err)
	}
}

func TestExport_RequiresTenantAndDir(t *testing.T) {
	s := memory.New()
	eng, _ := warden.NewEngine(warden.WithStore(s))
	if _, err := Export(context.Background(), eng, ExportOptions{}); err == nil {
		t.Fatal("expected error on missing TenantID")
	}
	if _, err := Export(context.Background(), eng, ExportOptions{TenantID: "t1"}); err == nil {
		t.Fatal("expected error on missing OutputDir")
	}
}
