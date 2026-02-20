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
