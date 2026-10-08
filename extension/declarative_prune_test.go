package extension

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// TestApplyDeclarative_PruneCoversNamespacesFromEveryPath runs the real
// declarative apply over two files. The second only opens an empty
// `namespace "ops"` block, which covers ops: a merge that drops the block
// leaves ops uncovered and its stale role alive. Namespaces neither file
// mentions are left alone.
func TestApplyDeclarative_PruneCoversNamespacesFromEveryPath(t *testing.T) {
	st := memory.New()
	ext := New(WithStore(st))
	if err := ext.Register(newTestApp("declarative-prune")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ctx := context.Background()
	for _, r := range []*role.Role{
		{TenantID: "t1", NamespacePath: "", Name: "keep", Slug: "keep"},
		{TenantID: "t1", NamespacePath: "", Name: "root-stale", Slug: "root-stale"},
		{TenantID: "t1", NamespacePath: "ops", Name: "ops-stale", Slug: "ops-stale"},
		{TenantID: "t1", NamespacePath: "legal", Name: "legal-stale", Slug: "legal-stale"},
	} {
		if err := st.CreateRole(ctx, r); err != nil {
			t.Fatalf("seed %s: %v", r.Slug, err)
		}
	}

	dir := t.TempDir()
	first := filepath.Join(dir, "a.warden")
	second := filepath.Join(dir, "b.warden")
	if err := os.WriteFile(first, []byte("warden config 1\ntenant t1\nrole keep {\n    name = \"keep\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("warden config 1\nnamespace \"ops\" {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ext.config.DeclarativePaths = []string{first, second}
	ext.config.DeclarativeTenantID = "t1"
	ext.config.DeclarativePrune = true
	if err := ext.applyDeclarative(ctx); err != nil {
		t.Fatalf("applyDeclarative: %v", err)
	}

	for _, gone := range []struct{ ns, slug string }{{"", "root-stale"}, {"ops", "ops-stale"}} {
		if _, err := st.GetRoleBySlug(ctx, "t1", gone.ns, gone.slug); err == nil {
			t.Errorf("role %q in %q survived the prune", gone.slug, gone.ns)
		}
	}
	for _, kept := range []struct{ ns, slug string }{{"", "keep"}, {"legal", "legal-stale"}} {
		if _, err := st.GetRoleBySlug(ctx, "t1", kept.ns, kept.slug); err != nil {
			t.Errorf("role %q in %q was pruned: %v", kept.slug, kept.ns, err)
		}
	}
}
