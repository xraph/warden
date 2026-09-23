package warden

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// seedAllow creates a tenant where user:alice may read document.
func seedAllow(t *testing.T, s *memory.Store) {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Reader", Slug: "reader"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	p := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{NamespacePath: "", Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	a := &assignment.Assignment{TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: "alice"}
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("create assignment: %v", err)
	}
}

func readReq() *CheckRequest {
	return &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "alice"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "doc1"},
		TenantID: "t1",
	}
}

// countCheckLogs drains the writer and returns how many entries landed.
func countCheckLogs(t *testing.T, eng *Engine, s *memory.Store) int {
	t.Helper()
	// The writer batches on a 250ms interval; give it room to flush.
	time.Sleep(400 * time.Millisecond)
	n, err := s.CountCheckLogs(context.Background(), checklogFilterForTenant("t1"))
	if err != nil {
		t.Fatalf("count check logs: %v", err)
	}
	return int(n)
}

func TestDryRunWritesNoCheckLog(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	ctx := context.Background()

	if _, err := eng.Check(ctx, readReq(), WithCallDryRun()); err != nil {
		t.Fatalf("dry run check: %v", err)
	}
	if got := countCheckLogs(t, eng, s); got != 0 {
		t.Fatalf("dry run wrote %d check log entries, want 0", got)
	}

	// The same check without the option still logs, so the test is not
	// passing because logging is broken.
	if _, err := eng.Check(ctx, readReq()); err != nil {
		t.Fatalf("normal check: %v", err)
	}
	if got := countCheckLogs(t, eng, s); got != 1 {
		t.Fatalf("normal check wrote %d check log entries, want 1", got)
	}
}

func TestDryRunNeitherReadsNorWritesCache(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	eng, err := NewEngine(WithStore(s), WithConfig(Config{CacheTTL: time.Minute}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	ctx := context.Background()

	// A dry run must not populate the cache, so a following normal check
	// still evaluates rather than being served a cached copy.
	if _, err := eng.Check(ctx, readReq(), WithCallDryRun()); err != nil {
		t.Fatalf("dry run: %v", err)
	}

	// Warm the cache with a real check, then revoke the grant in the store.
	if _, err := eng.Check(ctx, readReq()); err != nil {
		t.Fatalf("warming check: %v", err)
	}
	if err := s.DeleteAssignmentsBySubject(ctx, "t1", "user", "alice"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A normal check is served the stale allow from cache.
	cached, err := eng.Check(ctx, readReq())
	if err != nil {
		t.Fatalf("cached check: %v", err)
	}
	if !cached.Allowed {
		t.Fatal("expected the warm cache to serve a stale allow; cache may not be enabled")
	}

	// A dry run ignores that cache entry and evaluates against the store,
	// which no longer grants anything.
	fresh, err := eng.Check(ctx, readReq(), WithCallDryRun())
	if err != nil {
		t.Fatalf("dry run after revoke: %v", err)
	}
	if fresh.Allowed {
		t.Fatal("dry run was served a cached allow; it must bypass the cache read")
	}
}

// Returns a pointer: CountCheckLogs takes *QueryFilter, and Go cannot take
// the address of a function call result.
func checklogFilterForTenant(tenantID string) *checklog.QueryFilter {
	return &checklog.QueryFilter{TenantID: tenantID}
}
