package modules

import (
	"sync"
	"time"
)

const cacheTTL = 30 * time.Second

type cacheEntry struct {
	active    bool
	fetchedAt time.Time
}

// Cache provides a thread-safe in-memory cache for module active states.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

// NewCache creates an empty module state cache.
func NewCache() *Cache {
	return &Cache{entries: make(map[string]cacheEntry)}
}

// Get returns the cached active state and true if the entry exists and
// has not expired. Returns false, false when the cache has no valid entry.
func (c *Cache) Get(name string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[name]
	if !ok || time.Since(entry.fetchedAt) > cacheTTL {
		return false, false
	}
	return entry.active, true
}

// Set stores the active state for the given module name.
func (c *Cache) Set(name string, active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[name] = cacheEntry{active: active, fetchedAt: time.Now()}
}

// Invalidate removes a specific entry from the cache.
func (c *Cache) Invalidate(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, name)
}
