package filter

import (
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
)

// BlocklistFilter provides fast HASSH lookup with probabilistic membership testing
type BlocklistFilter struct {
	mu     sync.RWMutex
	filter *bloom.BloomFilter
	exact  map[string]bool // Fallback for verification
}

// NewBlocklistFilter creates a bloom filter sized for expected elements
// falsePositiveRate: typically 0.01 (1%) - lower = more memory
func NewBlocklistFilter(expectedElements uint, falsePositiveRate float64) *BlocklistFilter {
	return &BlocklistFilter{
		filter: bloom.NewWithEstimates(expectedElements, falsePositiveRate),
		exact:  make(map[string]bool),
	}
}

// Add inserts a HASSH fingerprint into the blocklist
func (b *BlocklistFilter) Add(hassh string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.filter.AddString(hassh)
	b.exact[hassh] = true
}

// Contains checks if a HASSH is blocked - O(k) where k is number of hash functions
// Returns false positives possible, true negatives guaranteed
func (b *BlocklistFilter) Contains(hassh string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Fast bloom filter check first
	if !b.filter.TestString(hassh) {
		return false // Definitely not blocked
	}

	// Verify with exact set to eliminate false positives
	return b.exact[hassh]
}

// Reload replaces the filter with new data
func (b *BlocklistFilter) Reload(blockedHashes []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Create new filter
	expectedElements := uint(len(blockedHashes))
	if expectedElements == 0 {
		expectedElements = 1000 // Minimum size
	}

	b.filter = bloom.NewWithEstimates(expectedElements, 0.01)
	b.exact = make(map[string]bool, len(blockedHashes))

	for _, hassh := range blockedHashes {
		b.filter.AddString(hassh)
		b.exact[hassh] = true
	}
}

// Count returns the number of blocked hashes
func (b *BlocklistFilter) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact)
}
