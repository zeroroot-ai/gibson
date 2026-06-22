package harness

import (
	"sort"
)

// Size limits for tag bags. These are hardcoded here; a future refactor
// should expose them via daemon config flags.
const (
	// MaxTagValueBytes caps the length of a single tag VALUE. Values
	// longer than this are truncated and marked in
	// gibson.truncated_keys.
	MaxTagValueBytes = 2048 // 2KB

	// MaxTotalBagBytes caps the total byte footprint of a single bag
	// (resource_tags or custom). When exceeded, low-precedence entries
	// are evicted first until the bag fits.
	MaxTotalBagBytes = 16384 // 16KB

	// MaxEntryCount caps the number of distinct keys in a single bag.
	MaxEntryCount = 256
)

// Marker keys stamped onto the signal when enforcement kicks in. These
// allow operators to detect misbehaving contributors via Cypher queries.
const (
	MarkerTruncatedKeys = "gibson.truncated_keys"
	MarkerDroppedKeys   = "gibson.size_dropped_keys"
)

// SizeEnforcer enforces per-value / per-bag byte limits and entry counts
// on merged tag bags. Run AFTER the merger has produced the final bag
// plus its keySources map.
type SizeEnforcer struct {
	metrics *ComplianceMetrics
}

// NewSizeEnforcer returns a SizeEnforcer with the given metrics. Pass nil
// to skip metric recording (tests).
func NewSizeEnforcer(metrics *ComplianceMetrics) *SizeEnforcer {
	return &SizeEnforcer{metrics: metrics}
}

// Enforce applies all three limits to a bag in place and returns the
// modified bag. keySources maps each key to its source precedence (1-5);
// eviction removes the LOWEST-precedence keys first (precedence 5 before
// precedence 1), preserving the most important tags.
//
// The returned `truncated` and `dropped` slices list the keys that were
// modified — callers can stamp them onto the signal as the marker entries.
func (e *SizeEnforcer) Enforce(bag map[string]string, keySources map[string]int) (truncated, dropped []string) {
	// 1. Truncate values that exceed MaxTagValueBytes.
	for k, v := range bag {
		if len(v) > MaxTagValueBytes {
			bag[k] = v[:MaxTagValueBytes-len("...[truncated]")] + "...[truncated]"
			truncated = append(truncated, k)
		}
	}

	// 2. Evict entries until entry count ≤ MaxEntryCount.
	for len(bag) > MaxEntryCount {
		k := e.lowestPrecedenceKey(bag, keySources)
		if k == "" {
			break
		}
		delete(bag, k)
		dropped = append(dropped, k)
	}

	// 3. Evict entries until total bytes ≤ MaxTotalBagBytes.
	for bagBytes(bag) > MaxTotalBagBytes {
		k := e.lowestPrecedenceKey(bag, keySources)
		if k == "" {
			break
		}
		delete(bag, k)
		dropped = append(dropped, k)
	}

	// Sort for deterministic marker output.
	sort.Strings(truncated)
	sort.Strings(dropped)

	return truncated, dropped
}

// lowestPrecedenceKey returns the key with the LOWEST-priority source (i.e.
// highest precedence number, since lower precedence wins = lower number).
// Returns "" if the bag is empty. Tie-breaking is alphabetical for
// determinism.
func (e *SizeEnforcer) lowestPrecedenceKey(bag map[string]string, keySources map[string]int) string {
	best := ""
	bestPrecedence := -1
	for k := range bag {
		p, ok := keySources[k]
		if !ok {
			p = PrecedenceDaemonDefaults // unknown source → treat as lowest
		}
		if p > bestPrecedence || (p == bestPrecedence && k < best) {
			bestPrecedence = p
			best = k
		}
	}
	return best
}

// bagBytes returns the total byte footprint of a bag (keys + values).
func bagBytes(bag map[string]string) int {
	total := 0
	for k, v := range bag {
		total += len(k) + len(v)
	}
	return total
}
