package ontology

// closure.go — transitive closure computation for subClassOf and sameAs graphs.
//
// All functions are pure (no lock acquisition) and are called from
// rebuildLocked under the write lock.

// computeAncestors computes the transitive ancestor sets for every IRI in the
// parents map. The result maps each IRI to an ordered slice of ancestor IRIs,
// from closest (direct parent) to farthest (root). Ordering within the same
// distance level is not specified.
func computeAncestors(parents map[string]map[string]struct{}) map[string][]string {
	result := make(map[string][]string, len(parents))

	// Memoised DFS.
	var visit func(iri string) []string
	visit = func(iri string) []string {
		if cached, ok := result[iri]; ok {
			return cached
		}
		// Mark as in-progress (nil = computing; avoid re-entrance on cycles,
		// which should not exist post-cycle-detection but be defensive).
		result[iri] = nil

		ps := parents[iri]
		if len(ps) == 0 {
			result[iri] = []string{}
			return result[iri]
		}

		seen := make(map[string]struct{})
		var ordered []string

		for p := range ps {
			if _, already := seen[p]; !already {
				seen[p] = struct{}{}
				ordered = append(ordered, p)
			}
			for _, grandParent := range visit(p) {
				if _, already := seen[grandParent]; !already {
					seen[grandParent] = struct{}{}
					ordered = append(ordered, grandParent)
				}
			}
		}

		result[iri] = ordered
		return ordered
	}

	for iri := range parents {
		visit(iri)
	}
	return result
}

// computeDescendants computes the transitive descendant sets for every IRI in
// the children map. The result maps each IRI to a flat slice of all
// descendants (any depth).
func computeDescendants(children map[string]map[string]struct{}) map[string][]string {
	result := make(map[string][]string, len(children))

	var visit func(iri string) []string
	visit = func(iri string) []string {
		if cached, ok := result[iri]; ok {
			return cached
		}
		result[iri] = nil // in-progress sentinel

		cs := children[iri]
		if len(cs) == 0 {
			result[iri] = []string{}
			return result[iri]
		}

		seen := make(map[string]struct{})
		var ordered []string

		for c := range cs {
			if _, already := seen[c]; !already {
				seen[c] = struct{}{}
				ordered = append(ordered, c)
			}
			for _, grandChild := range visit(c) {
				if _, already := seen[grandChild]; !already {
					seen[grandChild] = struct{}{}
					ordered = append(ordered, grandChild)
				}
			}
		}

		result[iri] = ordered
		return ordered
	}

	for iri := range children {
		visit(iri)
	}
	return result
}

// computeSameAsTransitive expands the sameAs graph to its transitive closure
// using BFS from each IRI. Returns a map from each IRI to all equivalent IRIs
// (excluding itself).
func computeSameAsTransitive(sameAs map[string]map[string]struct{}) map[string][]string {
	result := make(map[string][]string, len(sameAs))

	for start := range sameAs {
		visited := map[string]struct{}{start: {}}
		queue := []string{start}
		var equiv []string

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for neighbor := range sameAs[cur] {
				if _, seen := visited[neighbor]; !seen {
					visited[neighbor] = struct{}{}
					queue = append(queue, neighbor)
					equiv = append(equiv, neighbor)
				}
			}
		}
		result[start] = equiv
	}
	return result
}
