package brain

import "sort"

// deciderHostBudget bounds how many hosts the ambient projection puts in the
// Decider's context; the anomaly channel is always included beyond it.
const deciderHostBudget = 25

// ambient.go is focus-based ambient context projection (ADR-0005, gibson#749):
// instead of handing an agent/Decider the whole World, curate the *relevant* slice
// to fit a context budget. Relevance is the attention field (belief at any distance
// + surprise) — NOT a graph neighbourhood. The anomaly channel (surprised entities)
// is ALWAYS included even if its belief is low, so the unlooked-for breakthrough is
// never curated away. The periphery is dropped and reported as a count (LOD).
//
// (Associative/relationship-based expansion is a later refinement that needs the
// inter-entity relationship model; this is the attention-ranked + anomaly-channel
// projection, which works against the current belief field — placeholder or pgmpy.)

// AmbientProjection curates hosts for a context budget: the top-`budget` hosts by
// attention (descending), plus every surprised host (the anomaly channel) even if
// it falls outside the budget. Returns the kept hosts (attention desc, then a
// stable scope/address tiebreak) and the number of non-anomalous hosts omitted
// (the summarized periphery). budget <= 0 keeps everything.
func AmbientProjection(hosts []HostSnapshot, budget int) (kept []HostSnapshot, omitted int) {
	if len(hosts) == 0 {
		return nil, 0
	}
	ranked := append([]HostSnapshot(nil), hosts...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Attention != ranked[j].Attention {
			return ranked[i].Attention > ranked[j].Attention // higher attention first
		}
		if ranked[i].ScopeID != ranked[j].ScopeID {
			return ranked[i].ScopeID < ranked[j].ScopeID
		}
		return ranked[i].Address < ranked[j].Address
	})

	if budget <= 0 || len(ranked) <= budget {
		return ranked, 0
	}

	keptSet := map[string]bool{}
	key := func(h HostSnapshot) string { return h.ScopeID + "\x00" + h.Address + "\x00" + h.SSHHostKey }
	for _, h := range ranked[:budget] {
		kept = append(kept, h)
		keptSet[key(h)] = true
	}
	// Anomaly channel: always include surprised hosts outside the budget.
	for _, h := range ranked[budget:] {
		if h.Surprise != "" && !keptSet[key(h)] {
			kept = append(kept, h)
			keptSet[key(h)] = true
		}
	}
	for _, h := range ranked {
		if !keptSet[key(h)] {
			omitted++
		}
	}
	return kept, omitted
}

// AmbientHosts curates the engine's current hosts for the given budget (read path).
func (e *Engine) AmbientHosts(budget int) (kept []HostSnapshot, omitted int) {
	return AmbientProjection(e.Hosts(), budget)
}
