package warden

import (
	"container/list"
	"context"
	"encoding/json"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// memoryCacheShardCount is the number of independent shards the memory
// cache splits its entries across. Each shard has its own mutex, LRU list
// and secondary indexes, so unrelated tenants rarely contend on the same
// lock. A tenant's entries always live in exactly one shard (the shard is
// selected purely from the tenant ID), which is what makes
// InvalidateTenant/InvalidateSubject O(entries for that tenant) instead of
// a full-cache scan.
const memoryCacheShardCount = 32

// MemoryCache is the engine's built-in Cache implementation: a sharded,
// bounded, TTL'd LRU with O(1)-ish tenant/subject invalidation. It lives in
// the root package (rather than the cache/ subpackage) because the engine
// must be able to construct it directly from Config.CacheTTL /
// Config.CacheMaxSize without an import cycle — cache/ imports warden.
type MemoryCache struct {
	shards  [memoryCacheShardCount]*cacheShard
	ttl     time.Duration
	maxSize int
}

// MemoryCacheOption configures a MemoryCache.
type MemoryCacheOption func(*memoryCacheConfig)

type memoryCacheConfig struct {
	ttl     time.Duration
	maxSize int
}

// WithCacheTTL sets the cache entry time-to-live. Defaults to 5 minutes.
func WithCacheTTL(ttl time.Duration) MemoryCacheOption {
	return func(c *memoryCacheConfig) { c.ttl = ttl }
}

// WithCacheMaxSize sets the maximum number of entries the cache holds in
// total, across every shard. Defaults to 10000.
func WithCacheMaxSize(n int) MemoryCacheOption {
	return func(c *memoryCacheConfig) { c.maxSize = n }
}

// NewMemoryCache constructs the engine's built-in memory cache.
func NewMemoryCache(opts ...MemoryCacheOption) *MemoryCache {
	cfg := &memoryCacheConfig{ttl: 5 * time.Minute, maxSize: 10000}
	for _, opt := range opts {
		opt(cfg)
	}
	perShard := cfg.maxSize / memoryCacheShardCount
	if perShard < 1 {
		perShard = 1
	}
	m := &MemoryCache{ttl: cfg.ttl, maxSize: cfg.maxSize}
	for i := range m.shards {
		m.shards[i] = newCacheShard(perShard)
	}
	return m
}

// compile-time interface check.
var _ Cache = (*MemoryCache)(nil)

// cacheEntry is the value stored in a shard's LRU list.
type cacheEntry struct {
	key        string
	tenantID   string
	subjectKey string // "" when the request has no subject (never happens in practice)
	result     *CheckResult
	expiresAt  time.Time
}

// cacheShard is one independent partition of the cache: its own lock, LRU
// list, and secondary indexes for O(1) tenant/subject invalidation.
type cacheShard struct {
	mu      sync.Mutex
	maxSize int
	ll      *list.List
	items   map[string]*list.Element

	// tenantIdx and subjectIdx map an invalidation scope to the set of
	// cache keys currently holding an entry in that scope, so
	// InvalidateTenant/InvalidateSubject only touch the entries that
	// actually belong to that scope instead of scanning the shard.
	tenantIdx  map[string]map[string]struct{}
	subjectIdx map[string]map[string]struct{}

	// sf coalesces concurrent Set calls for the identical key so that a
	// cache-stampede of identical in-flight checks (all missing, all
	// recomputing the same result) only pays the LRU insert/eviction cost
	// once instead of once per goroutine.
	sf singleflight.Group
}

func newCacheShard(maxSize int) *cacheShard {
	return &cacheShard{
		maxSize:    maxSize,
		ll:         list.New(),
		items:      make(map[string]*list.Element),
		tenantIdx:  make(map[string]map[string]struct{}),
		subjectIdx: make(map[string]map[string]struct{}),
	}
}

func (m *MemoryCache) shardFor(tenantID string) *cacheShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenantID))
	return m.shards[h.Sum32()%memoryCacheShardCount]
}

// Get returns a cached check result, if present and not expired.
func (m *MemoryCache) Get(_ context.Context, tenantID, namespacePath string, req *CheckRequest) (*CheckResult, bool) {
	key := buildCacheKey(tenantID, namespacePath, req)
	shard := m.shardFor(tenantID)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	el, ok := shard.items[key]
	if !ok {
		return nil, false
	}
	entry, ok := el.Value.(*cacheEntry)
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		shard.removeElementLocked(el)
		return nil, false
	}
	shard.ll.MoveToFront(el)
	return entry.result, true
}

// Set stores a check result in the cache.
func (m *MemoryCache) Set(_ context.Context, tenantID, namespacePath string, req *CheckRequest, result *CheckResult) {
	key := buildCacheKey(tenantID, namespacePath, req)
	subjKey := subjectIndexKey(tenantID, string(req.Subject.Kind), req.Subject.ID)
	shard := m.shardFor(tenantID)

	// Coalesce identical concurrent writes: only the first caller for a
	// given key actually does the LRU/index work; the rest share its
	// outcome.
	_, err, _ := shard.sf.Do(key, func() (any, error) {
		shard.mu.Lock()
		defer shard.mu.Unlock()

		expiresAt := time.Now().Add(m.ttl)
		if el, ok := shard.items[key]; ok {
			if entry, ok := el.Value.(*cacheEntry); ok {
				entry.result = result
				entry.expiresAt = expiresAt
				shard.ll.MoveToFront(el)
				return nil, nil
			}
		}

		if shard.ll.Len() >= shard.maxSize {
			shard.evictOldestLocked()
		}

		entry := &cacheEntry{key: key, tenantID: tenantID, subjectKey: subjKey, result: result, expiresAt: expiresAt}
		el := shard.ll.PushFront(entry)
		shard.items[key] = el
		shard.indexAddLocked(shard.tenantIdx, tenantID, key)
		shard.indexAddLocked(shard.subjectIdx, subjKey, key)
		return nil, nil
	})
	if err != nil {
		// The loader above never returns a non-nil error; this branch
		// exists only so a future change that does return one isn't
		// silently swallowed.
		return
	}
}

// InvalidateTenant removes all cached results for a tenant. A tenant's
// entries always live in a single shard (shard selection is a pure
// function of tenantID), so this only ever locks one shard.
func (m *MemoryCache) InvalidateTenant(_ context.Context, tenantID string) {
	shard := m.shardFor(tenantID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	keys := shard.tenantIdx[tenantID]
	for k := range keys {
		if el, ok := shard.items[k]; ok {
			shard.removeElementLocked(el)
		}
	}
	delete(shard.tenantIdx, tenantID)
}

// InvalidateSubject removes all cached results for a specific subject,
// across every namespace it was checked in.
func (m *MemoryCache) InvalidateSubject(_ context.Context, tenantID string, subjectKind SubjectKind, subjectID string) {
	shard := m.shardFor(tenantID)
	subjKey := subjectIndexKey(tenantID, string(subjectKind), subjectID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	keys := shard.subjectIdx[subjKey]
	for k := range keys {
		if el, ok := shard.items[k]; ok {
			shard.removeElementLocked(el)
		}
	}
	delete(shard.subjectIdx, subjKey)
}

// Clear removes every cached entry across every tenant.
func (m *MemoryCache) Clear(_ context.Context) {
	for _, shard := range m.shards {
		shard.mu.Lock()
		shard.ll = list.New()
		shard.items = make(map[string]*list.Element)
		shard.tenantIdx = make(map[string]map[string]struct{})
		shard.subjectIdx = make(map[string]map[string]struct{})
		shard.mu.Unlock()
	}
}

// removeElementLocked removes el from the LRU list, the items map, and
// both secondary indexes. Caller must hold shard.mu.
func (s *cacheShard) removeElementLocked(el *list.Element) {
	entry, ok := el.Value.(*cacheEntry)
	if !ok {
		s.ll.Remove(el)
		return
	}
	s.ll.Remove(el)
	delete(s.items, entry.key)
	s.indexRemoveLocked(s.tenantIdx, entry.tenantID, entry.key)
	s.indexRemoveLocked(s.subjectIdx, entry.subjectKey, entry.key)
}

// evictOldestLocked drops the least-recently-used entry. Caller must hold
// shard.mu.
func (s *cacheShard) evictOldestLocked() {
	el := s.ll.Back()
	if el == nil {
		return
	}
	s.removeElementLocked(el)
}

func (s *cacheShard) indexAddLocked(idx map[string]map[string]struct{}, scope, key string) {
	set, ok := idx[scope]
	if !ok {
		set = make(map[string]struct{})
		idx[scope] = set
	}
	set[key] = struct{}{}
}

func (s *cacheShard) indexRemoveLocked(idx map[string]map[string]struct{}, scope, key string) {
	set, ok := idx[scope]
	if !ok {
		return
	}
	delete(set, key)
	if len(set) == 0 {
		delete(idx, scope)
	}
}

func subjectIndexKey(tenantID, kind, id string) string {
	return tenantID + "\x00" + kind + "\x00" + id
}

// buildCacheKey builds a collision-resistant cache key out of
// length-prefixed segments (so a colon or any other character inside a
// subject/resource ID can never be mistaken for a field boundary) plus an
// FNV hash of the canonical JSON encoding of the three attribute maps that
// can affect an ABAC decision. Empty/nil maps all hash to the same
// constant so two attribute-less requests share a cache entry.
func buildCacheKey(tenantID, namespacePath string, req *CheckRequest) string {
	var b strings.Builder
	writeSeg(&b, tenantID)
	writeSeg(&b, namespacePath)
	writeSeg(&b, string(req.Subject.Kind))
	writeSeg(&b, req.Subject.ID)
	writeSeg(&b, req.Action.Name)
	writeSeg(&b, req.Resource.Type)
	writeSeg(&b, req.Resource.ID)
	writeSeg(&b, hashAttrs(req.Subject.Attributes))
	writeSeg(&b, hashAttrs(req.Resource.Attributes))
	writeSeg(&b, hashAttrs(req.Context))
	return b.String()
}

// writeSeg appends a length-prefixed segment ("<len>:<content>") to b.
// Length-prefixing (rather than a plain separator like ":") means the
// content of one segment can never be mistaken for a boundary, however
// many colons, nulls, or other separator-looking bytes it contains.
func writeSeg(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
}

// emptyAttrsHash is the constant every nil/empty attribute map hashes to.
var emptyAttrsHash = fnvHex([]byte("{}"))

func hashAttrs(m map[string]any) string {
	if len(m) == 0 {
		return emptyAttrsHash
	}
	// encoding/json sorts map[string]any keys alphabetically (recursively
	// for nested maps), which gives us canonical JSON for free.
	b, err := json.Marshal(m)
	if err != nil {
		// Practically unreachable for the map[string]any values a
		// CheckRequest carries; fall back to a stable-enough encoding
		// rather than panicking on a hot path.
		b = []byte(strconv.Itoa(len(m)))
	}
	return fnvHex(b)
}

func fnvHex(b []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return strconv.FormatUint(h.Sum64(), 16)
}
