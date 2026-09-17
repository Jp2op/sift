// Package cache provides result caching for trivy-ai agent outputs.
// Caching is critical for cost control — the same CVE in the same package
// version with the same model should never trigger two LLM calls.
package cache

import (
	"sync"
	"time"

	"github.com/jp2op/trivy-ai/pkg/types"
)

// Cache stores and retrieves agent results keyed by a deterministic hash.
type Cache interface {
	Get(key string) (types.AgentResult, bool, error)
	Set(key string, result types.AgentResult, ttl time.Duration) error
	Stats() Stats
	Close() error
}

// Stats holds cache performance counters for a session.
type Stats struct {
	Hits   int
	Misses int
}

// HitRate returns the cache hit rate as a percentage (0-100).
func (s Stats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}

type entry struct {
	result    types.AgentResult
	expiresAt time.Time
}

// MemoryCache is an in-memory Cache implementation used in tests.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]entry
	stats   Stats
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: make(map[string]entry)}
}

func (m *MemoryCache) Get(key string) (types.AgentResult, bool, error) {
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()

	if !ok || time.Now().After(e.expiresAt) {
		m.mu.Lock()
		m.stats.Misses++
		m.mu.Unlock()
		return types.AgentResult{}, false, nil
	}

	m.mu.Lock()
	m.stats.Hits++
	m.mu.Unlock()

	result := e.result
	result.Cached = true
	return result, true, nil
}

func (m *MemoryCache) Set(key string, result types.AgentResult, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = entry{result: result, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryCache) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

func (m *MemoryCache) Close() error { return nil }