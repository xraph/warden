// Package cache provides caching implementations for Warden check results.
//
// Memory is a thin wrapper around the root package's warden.MemoryCache:
// the sharded LRU actually lives in package warden (cache_memory.go)
// because the engine must be able to construct it directly from
// Config.CacheTTL/CacheMaxSize without an import cycle (this package
// imports warden, so warden cannot import it back). This wrapper exists
// only so existing `cache.NewMemory(...)` call sites keep compiling.
package cache

import (
	"time"

	"github.com/xraph/warden"
)

// Memory is warden's built-in memory cache, re-exported from this
// subpackage for backward compatibility. New code should prefer
// warden.NewMemoryCache directly.
type Memory = warden.MemoryCache

// MemoryOption configures a Memory cache.
type MemoryOption = warden.MemoryCacheOption

// WithTTL sets the cache entry time-to-live.
func WithTTL(ttl time.Duration) MemoryOption { return warden.WithCacheTTL(ttl) }

// WithMaxSize sets the maximum number of cache entries.
func WithMaxSize(n int) MemoryOption { return warden.WithCacheMaxSize(n) }

// NewMemory creates a new in-memory cache backed by warden.NewMemoryCache.
func NewMemory(opts ...MemoryOption) *Memory {
	return warden.NewMemoryCache(opts...)
}
