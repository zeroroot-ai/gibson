package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Deduplicator identifies and merges duplicate findings based on content similarity.
// It maintains a hash index for fast duplicate detection and supports evidence merging.
//
// Thread-safety: All methods use read-write locks to ensure safe concurrent access.
type Deduplicator struct {
	mu        sync.RWMutex
	hashIndex map[string]types.ID           // hash -> finding ID
	findings  map[types.ID]*EnhancedFinding // finding ID -> finding
}

// DeduplicatorOption is a functional option for configuring the Deduplicator
type DeduplicatorOption func(*Deduplicator)

// NewDeduplicator creates a new Deduplicator with optional configuration
func NewDeduplicator(opts ...DeduplicatorOption) *Deduplicator {
	d := &Deduplicator{
		hashIndex: make(map[string]types.ID),
		findings:  make(map[types.ID]*EnhancedFinding),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// computeHash generates a SHA256 hash of the finding's key attributes.
// The hash is based on: title (normalized) + category + targetID (if present).
//
// This approach ensures:
//   - Same title/category/target = same hash (duplicate)
//   - Different evidence but same core issue = same hash (merge evidence)
//   - Title normalization handles minor variations in casing/whitespace
func computeHash(finding *EnhancedFinding) string {
	h := sha256.New()

	// Normalize title: lowercase and trim whitespace
	normalizedTitle := strings.ToLower(strings.TrimSpace(finding.Title))
	h.Write([]byte(normalizedTitle))

	// Include category
	h.Write([]byte(finding.Category))

	// Include target ID if present (findings against different targets are not duplicates)
	if finding.TargetID != nil {
		h.Write([]byte(finding.TargetID.String()))
	}

	// Return hex-encoded hash
	return hex.EncodeToString(h.Sum(nil))
}

// CheckDuplicate checks if a finding is a duplicate of an existing finding.
// Returns the existing finding's ID and true if a duplicate is found.
// Returns zero ID and false if the finding is unique.
//
// Thread-safe: Uses read lock for concurrent access.
func (d *Deduplicator) CheckDuplicate(finding *EnhancedFinding) (*types.ID, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	hash := computeHash(finding)
	existingID, found := d.hashIndex[hash]

	if found {
		return &existingID, true
	}

	return nil, false
}

// RegisterFinding registers a new finding in the deduplicator's hash index.
// This should be called after confirming the finding is not a duplicate.
//
// Thread-safe: Uses write lock for concurrent access.
func (d *Deduplicator) RegisterFinding(finding *EnhancedFinding) {
	d.mu.Lock()
	defer d.mu.Unlock()

	hash := computeHash(finding)
	d.hashIndex[hash] = finding.ID
	d.findings[finding.ID] = finding
}

// MergeEvidence merges evidence from a new finding into an existing finding.
// This is called when a duplicate is detected to accumulate evidence and
// track occurrence frequency.
//
// The merge operation:
//   - Appends new evidence to existing evidence
//   - Increments occurrence count
//   - Updates the last seen timestamp
//
// Returns an error if the existing finding is not found (should not happen
// if RegisterFinding was called correctly).
//
// Thread-safe: Uses write lock for concurrent access.
func (d *Deduplicator) MergeEvidence(existingID types.ID, newFinding *EnhancedFinding) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	existing, found := d.findings[existingID]
	if !found {
		return fmt.Errorf("existing finding %s not found in deduplicator", existingID)
	}

	// Append new evidence to existing finding
	existing.Evidence = append(existing.Evidence, newFinding.Evidence...)

	// Increment occurrence count and update timestamp
	existing.IncrementOccurrence()

	return nil
}

// FindRelated finds findings that are similar to the given finding based on
// keyword matching. This is a simple similarity check that doesn't use semantic
// analysis (for that, use an embedding-based approach).
//
// The threshold parameter (0.0 - 1.0) determines how similar findings must be:
//   - 1.0: Exact match only
//   - 0.5: Moderate similarity
//   - 0.0: Any match
//
// Returns:
//   - []types.ID: IDs of related findings, sorted by similarity (highest first)
//   - error: Non-nil if the operation fails
//
// Thread-safe: Uses read lock for concurrent access.
func (d *Deduplicator) FindRelated(finding *EnhancedFinding, threshold float64) ([]types.ID, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Extract keywords from the finding
	findingKeywords := extractKeywords(finding)

	// Score all findings by similarity
	type scoredFinding struct {
		id    types.ID
		score float64
	}

	var scored []scoredFinding

	for id, candidate := range d.findings {
		// Skip self
		if id == finding.ID {
			continue
		}

		// Calculate similarity score
		candidateKeywords := extractKeywords(candidate)
		similarity := computeSimilarity(findingKeywords, candidateKeywords)

		// Only include if above threshold
		if similarity >= threshold {
			scored = append(scored, scoredFinding{
				id:    id,
				score: similarity,
			})
		}
	}

	// Sort by score (highest first)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	// Extract IDs
	result := make([]types.ID, len(scored))
	for i, sf := range scored {
		result[i] = sf.id
	}

	return result, nil
}

// extractKeywords extracts significant keywords from a finding for similarity matching.
// Returns a normalized set of keywords (lowercase, deduplicated).
func extractKeywords(finding *EnhancedFinding) map[string]bool {
	keywords := make(map[string]bool)

	// Extract from title
	titleWords := strings.Fields(strings.ToLower(finding.Title))
	for _, word := range titleWords {
		// Skip common words (basic stopword filtering)
		if !isStopword(word) && len(word) > 2 {
			keywords[word] = true
		}
	}

	// Extract from category
	categoryWords := strings.Fields(strings.ToLower(finding.Category))
	for _, word := range categoryWords {
		if !isStopword(word) && len(word) > 2 {
			keywords[word] = true
		}
	}

	// Extract from description (first 100 chars to limit complexity)
	desc := finding.Description
	if len(desc) > 100 {
		desc = desc[:100]
	}
	descWords := strings.Fields(strings.ToLower(desc))
	for _, word := range descWords {
		if !isStopword(word) && len(word) > 2 {
			keywords[word] = true
		}
	}

	return keywords
}

// computeSimilarity calculates Jaccard similarity between two keyword sets.
// Returns a value between 0.0 (no overlap) and 1.0 (identical).
func computeSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0 // Both empty = identical
	}

	if len(a) == 0 || len(b) == 0 {
		return 0.0 // One empty = no similarity
	}

	// Count intersection
	intersection := 0
	for word := range a {
		if b[word] {
			intersection++
		}
	}

	// Union size = |A| + |B| - |A ∩ B|
	union := len(a) + len(b) - intersection

	// Jaccard similarity = |A ∩ B| / |A ∪ B|
	return float64(intersection) / float64(union)
}

// isStopword checks if a word is a common stopword that should be ignored
func isStopword(word string) bool {
	stopwords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"but": true, "in": true, "on": true, "at": true, "to": true,
		"for": true, "of": true, "with": true, "by": true, "from": true,
		"is": true, "are": true, "was": true, "were": true, "be": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"do": true, "does": true, "did": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
		"can": true, "this": true, "that": true, "these": true, "those": true,
	}

	return stopwords[word]
}

// Count returns the total number of findings tracked by the deduplicator
func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.findings)
}

// Clear removes all findings from the deduplicator
func (d *Deduplicator) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.hashIndex = make(map[string]types.ID)
	d.findings = make(map[types.ID]*EnhancedFinding)
}

// GetFinding retrieves a finding by ID
func (d *Deduplicator) GetFinding(id types.ID) (*EnhancedFinding, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	finding, found := d.findings[id]
	return finding, found
}
