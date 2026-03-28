package intelligence

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("intelligence service circuit breaker is open")

// queryCache provides thread-safe caching for query results.
type queryCache struct {
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

// cacheEntry holds a cached value with expiration.
type cacheEntry struct {
	value     any
	expiresAt time.Time
}

// newQueryCache creates a new query cache.
func newQueryCache() *queryCache {
	return &queryCache{
		entries: make(map[string]*cacheEntry),
	}
}

// key generates a cache key from a prefix and options.
func (c *queryCache) key(prefix string, opts any) string {
	return fmt.Sprintf("%s:%v", prefix, opts)
}

// get retrieves a value from the cache if it exists and hasn't expired.
func (c *queryCache) get(key string) any {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.value
}

// set stores a value in the cache with a TTL.
func (c *queryCache) set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

// delete removes a key from the cache.
func (c *queryCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
}

// clear removes all entries from the cache.
func (c *queryCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
}

// cleanup removes expired entries from the cache.
func (c *queryCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// size returns the number of entries in the cache.
func (c *queryCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}
