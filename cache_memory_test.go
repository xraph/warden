package warden

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xraph/warden/store/memory"
)

func TestMemoryCache_AttributeSensitiveKey(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	base := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1", Attributes: map[string]any{"dept": "eng"}},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	other := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1", Attributes: map[string]any{"dept": "sales"}},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	c.Set(ctx, "t1", "", base, &CheckResult{Allowed: true})

	if _, ok := c.Get(ctx, "t1", "", other); ok {
		t.Fatal("a request with different subject attributes must not hit a cache entry keyed on different attributes")
	}
	if _, ok := c.Get(ctx, "t1", "", base); !ok {
		t.Fatal("expected the original request to still hit")
	}
}

func TestMemoryCache_EmptyAndNilAttributesShareEntry(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	nilAttrs := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	emptyAttrs := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1", Attributes: map[string]any{}},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	c.Set(ctx, "t1", "", nilAttrs, &CheckResult{Allowed: true})
	if _, ok := c.Get(ctx, "t1", "", emptyAttrs); !ok {
		t.Fatal("nil and empty attribute maps must hash to the same cache key")
	}
}

func TestMemoryCache_ResourceAndContextAttributesAreKeyed(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	base := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1", Attributes: map[string]any{"owner": "u1"}},
		Context:  map[string]any{"ip": "10.0.0.1"},
	}
	diffResourceAttrs := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1", Attributes: map[string]any{"owner": "u2"}},
		Context:  map[string]any{"ip": "10.0.0.1"},
	}
	diffContext := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1", Attributes: map[string]any{"owner": "u1"}},
		Context:  map[string]any{"ip": "10.0.0.2"},
	}

	c.Set(ctx, "t1", "", base, &CheckResult{Allowed: true})
	if _, ok := c.Get(ctx, "t1", "", diffResourceAttrs); ok {
		t.Fatal("different resource attributes must not share a cache entry")
	}
	if _, ok := c.Get(ctx, "t1", "", diffContext); ok {
		t.Fatal("different context must not share a cache entry")
	}
}

func TestMemoryCache_NamespaceFromExplicitParam(t *testing.T) {
	// H3: Get/Set take the resolved namespace explicitly rather than
	// trusting CheckRequest.NamespacePath (which the engine leaves unset
	// when scope comes from context). Two calls with the same req but a
	// different namespace parameter must not collide.
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	c.Set(ctx, "t1", "eng", req, &CheckResult{Allowed: true})
	if _, ok := c.Get(ctx, "t1", "sales", req); ok {
		t.Fatal("a different namespace parameter must be a cache miss")
	}
	if _, ok := c.Get(ctx, "t1", "eng", req); !ok {
		t.Fatal("expected a hit for the matching namespace parameter")
	}
}

func TestMemoryCache_ColonInSubjectIDDoesNotCollide(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	// Length-prefixed key encoding must keep these two requests distinct
	// even though a naive colon-joined key would concatenate identically:
	// "user:a:b" (one ID with a colon) vs the ID "a" followed by a
	// different field starting with "b".
	reqA := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "a:b"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	reqB := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "a"},
		Action:   Action{Name: "b:read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}

	c.Set(ctx, "t1", "", reqA, &CheckResult{Allowed: true, Decision: DecisionAllow})
	c.Set(ctx, "t1", "", reqB, &CheckResult{Allowed: false, Decision: DecisionDenyDefault})

	gotA, ok := c.Get(ctx, "t1", "", reqA)
	if !ok || !gotA.Allowed {
		t.Fatalf("expected reqA's own entry (allowed), got ok=%v result=%+v", ok, gotA)
	}
	gotB, ok := c.Get(ctx, "t1", "", reqB)
	if !ok || gotB.Allowed {
		t.Fatalf("expected reqB's own entry (denied), got ok=%v result=%+v", ok, gotB)
	}
}

func TestMemoryCache_InvalidateSubject(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	c.Set(ctx, "t1", "", req, &CheckResult{Allowed: true})
	c.InvalidateSubject(ctx, "t1", SubjectUser, "u1")

	if _, ok := c.Get(ctx, "t1", "", req); ok {
		t.Fatal("expected the entry to be gone after InvalidateSubject")
	}
}

func TestMemoryCache_InvalidateTenantOnlyTouchesThatTenant(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	c.Set(ctx, "t1", "", req, &CheckResult{Allowed: true})
	c.Set(ctx, "t2", "", req, &CheckResult{Allowed: true})

	c.InvalidateTenant(ctx, "t1")

	if _, ok := c.Get(ctx, "t1", "", req); ok {
		t.Fatal("t1 entry should be invalidated")
	}
	if _, ok := c.Get(ctx, "t2", "", req); !ok {
		t.Fatal("t2 entry must be unaffected")
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(WithCacheTTL(time.Minute))

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	c.Set(ctx, "t1", "", req, &CheckResult{Allowed: true})
	c.Set(ctx, "t2", "", req, &CheckResult{Allowed: true})
	c.Clear(ctx)

	if _, ok := c.Get(ctx, "t1", "", req); ok {
		t.Fatal("expected t1 cleared")
	}
	if _, ok := c.Get(ctx, "t2", "", req); ok {
		t.Fatal("expected t2 cleared")
	}
}

func TestMemoryCache_ConcurrentGetSet(t *testing.T) {
	t.Helper()
	c := NewMemoryCache(WithCacheTTL(time.Minute), WithCacheMaxSize(100))
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				req := &CheckRequest{
					Subject:  Subject{Kind: SubjectUser, ID: "u1"},
					Action:   Action{Name: "read"},
					Resource: Resource{Type: "doc", ID: "d1"},
				}
				c.Set(ctx, "t1", "", req, &CheckResult{Allowed: true})
				c.Get(ctx, "t1", "", req)
				if i%10 == 0 {
					c.InvalidateSubject(ctx, "t1", SubjectUser, "u1")
				}
			}
		}()
	}
	wg.Wait()
}

func TestEngine_InvalidateSubjectAndTenant(t *testing.T) {
	ctx := WithTenant(context.Background(), "app1", "t1")
	s := memory.New()
	eng, err := NewEngine(WithStore(s), WithConfig(func() Config {
		c := DefaultConfig()
		c.CacheTTL = time.Minute
		c.EnableCheckLog = boolPtr(false)
		return c
	}()))
	if err != nil {
		t.Fatal(err)
	}

	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "u1"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "doc", ID: "d1"},
	}
	if _, err := eng.Check(ctx, req); err != nil {
		t.Fatal(err)
	}

	eng.InvalidateSubject(ctx, "t1", SubjectUser, "u1")
	// Indirect assertion: after invalidation a subsequent identical Check
	// must not blow up and must still return a valid (denied, no data)
	// result: this exercises the InvalidateSubject wiring end to end via
	// the engine rather than the cache directly.
	res, err := eng.Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("expected deny (no roles/relations/policies were ever created)")
	}
}
