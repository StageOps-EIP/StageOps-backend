package modules

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCache_SetAndGet(t *testing.T) {
	c := NewCache()

	c.Set("lumiere", true)
	active, ok := c.Get("lumiere")

	assert.True(t, ok)
	assert.True(t, active)
}

func TestCache_GetMiss(t *testing.T) {
	c := NewCache()

	_, ok := c.Get("son")
	assert.False(t, ok)
}

func TestCache_Invalidate(t *testing.T) {
	c := NewCache()

	c.Set("lumiere", true)
	c.Invalidate("lumiere")

	_, ok := c.Get("lumiere")
	assert.False(t, ok)
}

func TestCache_Expiry(t *testing.T) {
	c := NewCache()

	// Manually inject an expired entry.
	c.mu.Lock()
	c.entries["lumiere"] = cacheEntry{
		active:    true,
		fetchedAt: time.Now().Add(-31 * time.Second),
	}
	c.mu.Unlock()

	_, ok := c.Get("lumiere")
	assert.False(t, ok, "expired entry should not be returned")
}

func TestCache_SetOverwrite(t *testing.T) {
	c := NewCache()

	c.Set("son", true)
	c.Set("son", false)

	active, ok := c.Get("son")
	assert.True(t, ok)
	assert.False(t, active)
}
