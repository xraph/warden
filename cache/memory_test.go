package cache

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden"
)

func TestMemoryCacheHitMiss(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithTTL(time.Minute))

	req := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "d1"},
	}
	result := &warden.CheckResult{Allowed: true, Decision: warden.DecisionAllow}

	// Miss
	_, ok := c.Get(ctx, "t1", req)
	if ok {
		t.Fatal("expected cache miss")
	}

	// Set + Hit
	c.Set(ctx, "t1", req, result)
	got, ok := c.Get(ctx, "t1", req)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if !got.Allowed {
		t.Fatal("expected allowed")
	}
}

func TestMemoryCacheTTLExpiry(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithTTL(1 * time.Millisecond))

	req := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "d1"},
	}
	result := &warden.CheckResult{Allowed: true}

	c.Set(ctx, "t1", req, result)
	time.Sleep(5 * time.Millisecond)

	_, ok := c.Get(ctx, "t1", req)
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestMemoryCacheInvalidateTenant(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()

	req1 := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "doc", ID: "d1"},
	}
	req2 := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u2"},
		Action:   warden.Action{Name: "write"},
		Resource: warden.Resource{Type: "doc", ID: "d2"},
	}

	c.Set(ctx, "t1", req1, &warden.CheckResult{Allowed: true})
	c.Set(ctx, "t1", req2, &warden.CheckResult{Allowed: false})
	c.Set(ctx, "t2", req1, &warden.CheckResult{Allowed: true})

	c.InvalidateTenant(ctx, "t1")

	if _, ok := c.Get(ctx, "t1", req1); ok {
		t.Fatal("t1 req1 should be invalidated")
	}
	if _, ok := c.Get(ctx, "t1", req2); ok {
		t.Fatal("t1 req2 should be invalidated")
	}
	if _, ok := c.Get(ctx, "t2", req1); !ok {
		t.Fatal("t2 req1 should still be cached")
	}
}

func TestMemoryCacheInvalidateSubject(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()

	req1 := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "doc", ID: "d1"},
	}
	req2 := &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u2"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "doc", ID: "d1"},
	}

	c.Set(ctx, "t1", req1, &warden.CheckResult{Allowed: true})
	c.Set(ctx, "t1", req2, &warden.CheckResult{Allowed: true})

	c.InvalidateSubject(ctx, "t1", warden.SubjectUser, "u1")

	if _, ok := c.Get(ctx, "t1", req1); ok {
		t.Fatal("u1 should be invalidated")
	}
	if _, ok := c.Get(ctx, "t1", req2); !ok {
		t.Fatal("u2 should still be cached")
	}
}

// TestMemoryCacheNamespaceIsolation guards against caching a check result computed
// for one namespace and returning it for another. Role assignments are commonly
// scoped per-namespace (e.g. per workspace/tenant subtree), so two requests that are
// identical except for NamespacePath can have different outcomes and must not share
// a cache entry.
func TestMemoryCacheNamespaceIsolation(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithTTL(time.Minute))

	reqA := &warden.CheckRequest{
		NamespacePath: "ws-A",
		Subject:       warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:        warden.Action{Name: "create"},
		Resource:      warden.Resource{Type: "connections"},
	}
	reqB := &warden.CheckRequest{
		NamespacePath: "ws-B",
		Subject:       warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:        warden.Action{Name: "create"},
		Resource:      warden.Resource{Type: "connections"},
	}

	// Allowed in namespace ws-A only.
	c.Set(ctx, "t1", reqA, &warden.CheckResult{Allowed: true, Decision: warden.DecisionAllow})

	// A different namespace must be a cache miss, not the ws-A result.
	if _, ok := c.Get(ctx, "t1", reqB); ok {
		t.Fatal("namespace ws-B got a cache hit from a ws-A entry (cross-namespace leak)")
	}

	// The exact same request (ws-A) must still hit.
	if _, ok := c.Get(ctx, "t1", reqA); !ok {
		t.Fatal("expected cache hit for the same namespace")
	}
}

// TestMemoryCacheInvalidateSubjectAcrossNamespaces ensures invalidating a subject
// clears its entries in every namespace, not just one.
func TestMemoryCacheInvalidateSubjectAcrossNamespaces(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()

	mk := func(ns, user string) *warden.CheckRequest {
		return &warden.CheckRequest{
			NamespacePath: ns,
			Subject:       warden.Subject{Kind: warden.SubjectUser, ID: user},
			Action:        warden.Action{Name: "read"},
			Resource:      warden.Resource{Type: "doc"},
		}
	}

	c.Set(ctx, "t1", mk("ws-A", "u1"), &warden.CheckResult{Allowed: true})
	c.Set(ctx, "t1", mk("ws-B", "u1"), &warden.CheckResult{Allowed: true})
	c.Set(ctx, "t1", mk("ws-A", "u2"), &warden.CheckResult{Allowed: true})

	c.InvalidateSubject(ctx, "t1", warden.SubjectUser, "u1")

	if _, ok := c.Get(ctx, "t1", mk("ws-A", "u1")); ok {
		t.Fatal("u1 ws-A should be invalidated")
	}
	if _, ok := c.Get(ctx, "t1", mk("ws-B", "u1")); ok {
		t.Fatal("u1 ws-B should be invalidated across all namespaces")
	}
	if _, ok := c.Get(ctx, "t1", mk("ws-A", "u2")); !ok {
		t.Fatal("u2 must not be invalidated when invalidating u1")
	}
}

func TestMemoryCacheMaxSize(t *testing.T) {
	ctx := context.Background()
	c := NewMemory(WithMaxSize(2))

	for i := 0; i < 5; i++ {
		req := &warden.CheckRequest{
			Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
			Action:   warden.Action{Name: "read"},
			Resource: warden.Resource{Type: "doc", ID: string(rune('a' + i))},
		}
		c.Set(ctx, "t1", req, &warden.CheckResult{Allowed: true})
	}

	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()
	if size > 2 {
		t.Fatalf("expected max 2 entries, got %d", size)
	}
}
