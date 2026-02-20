// Package cache provides caching implementations for Warden check results.
package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/xraph/warden"
)

// Compile-time interface check.
var _ warden.Cache = (*Memory)(nil)

// Memory is an in-memory LRU-like cache with TTL-based expiration.
type Memory struct {
	mu      sync.RWMutex
	entries map[string]*entry
	ttl     time.Duration
	maxSize int
}

type entry struct {
	result    *warden.CheckResult
	expiresAt time.Time
}

// MemoryOption configures the memory cache.
type MemoryOption func(*Memory)

// WithTTL sets the cache entry time-to-live.
func WithTTL(ttl time.Duration) MemoryOption {
	return func(m *Memory) { m.ttl = ttl }
}

// WithMaxSize sets the maximum number of cache entries.
func WithMaxSize(n int) MemoryOption {
	return func(m *Memory) { m.maxSize = n }
}

// NewMemory creates a new in-memory cache.
func NewMemory(opts ...MemoryOption) *Memory {
	m := &Memory{
		entries: make(map[string]*entry),
		ttl:     5 * time.Minute,
		maxSize: 10000,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Get returns a cached check result.
func (m *Memory) Get(_ context.Context, tenantID string, req *warden.CheckRequest) (*warden.CheckResult, bool) {
	key := cacheKey(tenantID, req)
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		m.mu.Lock()
		delete(m.entries, key)
		m.mu.Unlock()
		return nil, false
	}
	return e.result, true
}

// Set stores a check result in the cache.
func (m *Memory) Set(_ context.Context, tenantID string, req *warden.CheckRequest, result *warden.CheckResult) {
	key := cacheKey(tenantID, req)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Evict if at capacity.
	if len(m.entries) >= m.maxSize {
		m.evictExpired()
		if len(m.entries) >= m.maxSize {
			// Evict oldest entry.
			m.evictOne()
		}
	}

	m.entries[key] = &entry{
		result:    result,
		expiresAt: time.Now().Add(m.ttl),
	}
}

// InvalidateTenant removes all cached results for a tenant.
func (m *Memory) InvalidateTenant(_ context.Context, tenantID string) {
	prefix := tenantID + ":"
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.entries {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			delete(m.entries, k)
		}
	}
}

// InvalidateSubject removes all cached results for a specific subject.
func (m *Memory) InvalidateSubject(_ context.Context, tenantID string, subjectKind warden.SubjectKind, subjectID string) {
	subKey := fmt.Sprintf("%s:%s:%s:", tenantID, subjectKind, subjectID)
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.entries {
		if len(k) >= len(subKey) && k[:len(subKey)] == subKey {
			delete(m.entries, k)
		}
	}
}

func cacheKey(tenantID string, req *warden.CheckRequest) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		tenantID,
		req.Subject.Kind,
		req.Subject.ID,
		req.Action.Name,
		req.Resource.Type,
		req.Resource.ID,
	)
}

// evictExpired removes all expired entries. Must hold write lock.
func (m *Memory) evictExpired() {
	now := time.Now()
	for k, e := range m.entries {
		if now.After(e.expiresAt) {
			delete(m.entries, k)
		}
	}
}

// evictOne removes one arbitrary entry. Must hold write lock.
func (m *Memory) evictOne() {
	for k := range m.entries {
		delete(m.entries, k)
		return
	}
}
