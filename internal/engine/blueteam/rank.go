// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"fmt"
	"math"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// Ranked is a finding that is not `verified`, with the belief of its target.
type Ranked struct {
	brain.FindingSnapshot
	// Belief is the belief that the target is worth the attack (Juicy of the
	// Host of the finding). It is 0 when the finding has no Host in the World.
	Belief float64
	// Tier is 0 for P1 or a critical finding with no priority, up to 3.
	Tier int
}

// OpenRanked returns the findings with a status other than `verified`, with
// the tier and the belief of each. The order is the order of Key.
func OpenRanked(findings []brain.FindingSnapshot, hosts []brain.HostSnapshot) []Ranked {
	belief := map[string]float64{}
	for _, h := range hosts {
		belief[h.ScopeID+"\x00"+h.Address] = h.Belief.Juicy
	}
	var out []Ranked
	for _, f := range findings {
		if f.Status == brain.FindingStatusVerified {
			continue
		}
		out = append(out, Ranked{
			FindingSnapshot: f, Tier: tier(f), Belief: belief[f.ScopeID+"\x00"+f.Address],
		})
	}
	return out
}

// tier is the place of a finding in the order. A finding with a priority uses
// it. A finding with no priority yet uses its severity, as if critical were P1,
// high P2, medium P3 and any other severity P4.
func tier(f brain.FindingSnapshot) int {
	if p := finding.Priority(f.Priority); p.IsValid() {
		return p.Rank() - 1
	}
	switch strings.ToLower(f.Severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

// Key is the sort key of a ranked finding. It sorts the tier first, then the
// belief from high to low, then the id so that the key is unique.
func Key(r Ranked) string {
	b := math.Min(1, math.Max(0, r.Belief))
	return fmt.Sprintf("%d\x00%010d\x00%s", r.Tier, int64(math.Round((1-b)*1e9)), r.ID)
}
