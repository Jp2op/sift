package cache_test

import (
	"testing"
	"time"

	"github.com/jp2op/trivy-ai/internal/cache"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func testResult(id string) types.AgentResult {
	return types.AgentResult{
		FindingID: id,
		AgentName: "explain",
		Content:   "Test explanation for " + id,
		Usage:     types.Usage{PromptTokens: 100, CompletionTokens: 50},
	}
}

func TestMemoryCache_SetGet(t *testing.T) {
	c := cache.NewMemoryCache()
	result := testResult("CVE-2024-1234")
	_ = c.Set("key1", result, time.Minute)

	got, ok, err := c.Get("key1")
	if err != nil { t.Fatalf("Get() error: %v", err) }
	if !ok { t.Fatal("Get() returned false, want true") }
	if got.FindingID != result.FindingID {
		t.Errorf("FindingID = %q, want %q", got.FindingID, result.FindingID)
	}
}

func TestMemoryCache_Miss(t *testing.T) {
	c := cache.NewMemoryCache()
	_, ok, err := c.Get("nonexistent")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if ok { t.Error("Get() returned true for nonexistent key") }
}

func TestMemoryCache_TTLExpiry(t *testing.T) {
	c := cache.NewMemoryCache()
	_ = c.Set("expiring", testResult("CVE-1"), 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	_, ok, _ := c.Get("expiring")
	if ok { t.Error("Get() returned true for expired key") }
}

func TestMemoryCache_Stats(t *testing.T) {
	c := cache.NewMemoryCache()
	_ = c.Set("k1", testResult("CVE-1"), time.Minute)
	c.Get("k1")
	c.Get("k1")
	c.Get("missing")
	s := c.Stats()
	if s.Hits != 2 { t.Errorf("Hits = %d, want 2", s.Hits) }
	if s.Misses != 1 { t.Errorf("Misses = %d, want 1", s.Misses) }
}

func TestMemoryCache_CachedFlag(t *testing.T) {
	c := cache.NewMemoryCache()
	_ = c.Set("key", testResult("CVE-1"), time.Minute)
	got, _, _ := c.Get("key")
	if !got.Cached { t.Error("Get() should set Cached=true on hit") }
}

func TestMemoryCache_HitRate(t *testing.T) {
	s := cache.Stats{Hits: 3, Misses: 1}
	if s.HitRate() != 75.0 { t.Errorf("HitRate() = %v, want 75.0", s.HitRate()) }
}

func TestMemoryCache_Interface(t *testing.T) {
	var _ cache.Cache = (*cache.MemoryCache)(nil)
}