package dsl

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// storeDefaultLimit mirrors the cap every backend applies when a ListFilter
// carries no Limit. The tests below seed more rows than this so a single
// unpaginated List* call cannot return the whole set.
const storeDefaultLimit = 1000

func seedRoles(t *testing.T, s *memory.Store, tenantID string, n int) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC()
	for i := range n {
		r := &role.Role{
			ID:        id.NewRoleID(),
			TenantID:  tenantID,
			Name:      fmt.Sprintf("Role %04d", i),
			Slug:      fmt.Sprintf("role-%04d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
			UpdatedAt: base,
		}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("seed role %d: %v", i, err)
		}
	}
}

func seedPermissions(t *testing.T, s *memory.Store, tenantID string, n int) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC()
	for i := range n {
		p := &permission.Permission{
			ID:        id.NewPermissionID(),
			TenantID:  tenantID,
			Name:      fmt.Sprintf("doc:act%04d", i),
			Resource:  "doc",
			Action:    fmt.Sprintf("act%04d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
			UpdatedAt: base,
		}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("seed permission %d: %v", i, err)
		}
	}
}

// TestBuildProgram_ExportsPastStoreDefaultLimit proves `warden export` emits
// every row a tenant owns rather than the first page the store hands back.
func TestBuildProgram_ExportsPastStoreDefaultLimit(t *testing.T) {
	const n = storeDefaultLimit + 237

	mem := memory.New()
	seedRoles(t, mem, "t1", n)
	seedPermissions(t, mem, "t1", n)

	eng, err := warden.NewEngine(warden.WithStore(&cappingStore{mem}))
	if err != nil {
		t.Fatal(err)
	}

	prog, err := BuildProgram(context.Background(), eng, ExportOptions{TenantID: "t1"})
	if err != nil {
		t.Fatalf("build program: %v", err)
	}
	if len(prog.Roles) != n {
		t.Errorf("exported roles: got %d, want %d", len(prog.Roles), n)
	}
	if len(prog.Permissions) != n {
		t.Errorf("exported permissions: got %d, want %d", len(prog.Permissions), n)
	}
}

// TestApply_PrunePastStoreDefaultLimit proves an apply with prune reconciles
// the whole tenant. A prune that only sees the first page leaves undeclared
// rows behind while reporting success.
func TestApply_PrunePastStoreDefaultLimit(t *testing.T) {
	const n = storeDefaultLimit + 237

	mem := memory.New()
	seedRoles(t, mem, "t1", n)

	eng, err := warden.NewEngine(warden.WithStore(&cappingStore{mem}))
	if err != nil {
		t.Fatal(err)
	}

	src := `warden config 1
tenant t1

role keeper {
    name = "Keeper"
}
`
	prog, errs := Parse("prune", []byte(src))
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{Prune: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	left, err := mem.CountRoles(context.Background(), &role.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Errorf("roles left after prune: got %d, want 1 (only the declared role)", left)
	}
}

// TestCollectPages_RejectsBackendThatIgnoresOffset guards the accumulator
// against spinning forever on a store that returns a full page regardless of
// the offset it was handed.
func TestCollectPages_RejectsBackendThatIgnoresOffset(t *testing.T) {
	calls := 0
	_, err := collectPages(func(limit, _ int) ([]int, error) {
		calls++
		return make([]int, limit), nil
	})
	if !errors.Is(err, errListTooLarge) {
		t.Fatalf("want errListTooLarge, got %v after %d calls", err, calls)
	}
}

// TestFindResourceType_PastStoreDefaultLimit proves permission-expression
// resolution finds a resource type that sorts beyond the store's first page.
// A namespace-wide scan that stops at the default limit silently denies every
// check against the resource types it never saw.
func TestFindResourceType_PastStoreDefaultLimit(t *testing.T) {
	const n = storeDefaultLimit + 237

	mem := memory.New()
	ctx := context.Background()
	base := time.Now().UTC()
	for i := range n {
		rt := &resourcetype.ResourceType{
			ID:        id.NewResourceTypeID(),
			TenantID:  "t1",
			Name:      fmt.Sprintf("kind%04d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
			UpdatedAt: base,
		}
		if err := mem.CreateResourceType(ctx, rt); err != nil {
			t.Fatalf("seed resource type %d: %v", i, err)
		}
	}

	ev := NewEngineEvaluator(&cappingStore{mem})

	// The last-created resource type sorts onto the final page.
	want := fmt.Sprintf("kind%04d", n-1)
	got, ns := ev.findResourceType(ctx, "t1", "", want)
	if got == nil {
		t.Fatalf("findResourceType(%q): got nil, want the seeded resource type", want)
	}
	if got.Name != want {
		t.Errorf("resource type name: got %q, want %q", got.Name, want)
	}
	if ns != "" {
		t.Errorf("namespace: got %q, want the tenant root", ns)
	}
}
