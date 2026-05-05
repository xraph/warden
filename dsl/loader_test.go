package dsl

import (
	"context"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"
)

func TestLoadDir_MergesFiles(t *testing.T) {
	prog, errs, err := LoadDir("testdata/multi-file")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("expected no diagnostics, got %v", errs)
	}
	if prog.Tenant != "t1" {
		t.Errorf("tenant = %q", prog.Tenant)
	}
	if len(prog.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(prog.Permissions))
	}
	if len(prog.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(prog.Roles))
	}
}

func TestLoadDir_ApplyEndToEnd(t *testing.T) {
	prog, _, err := LoadDir("testdata/multi-file")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if r, err := s.GetRoleBySlug(context.Background(), "t1", "", "editor"); err != nil || r == nil {
		t.Fatalf("editor role missing: %v", err)
	}
}
