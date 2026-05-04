package saga

import (
	"fmt"
	"strings"
)

// TopoSort returns the steps in a valid topological order based on each
// step's Requires() declarations. Returns an error if the graph contains
// a cycle, or if any step references a name that does not appear in the
// input slice.
//
// Sort is stable: among steps that are mutually independent, the original
// input order is preserved. This makes operator logs and Tenant.status
// readable — Phase 1 steps come before Phase 2 even when both have empty
// Requires().
func TopoSort(steps []Step) ([]Step, error) {
	// 1) Build a name → Step map and validate uniqueness.
	byName := make(map[string]Step, len(steps))
	order := make([]string, 0, len(steps))
	for _, s := range steps {
		name := s.Name()
		if name == "" {
			return nil, fmt.Errorf("saga.TopoSort: step has empty Name()")
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("saga.TopoSort: duplicate step name %q", name)
		}
		byName[name] = s
		order = append(order, name)
	}

	// 2) Validate every Requires() reference exists.
	for _, s := range steps {
		for _, dep := range s.Requires() {
			if _, ok := byName[dep]; !ok {
				return nil, fmt.Errorf("saga.TopoSort: step %q requires unknown step %q", s.Name(), dep)
			}
		}
	}

	// 3) Kahn's algorithm — track in-degree and ready set, but iterate
	//    `order` so ties resolve to original input order.
	indeg := make(map[string]int, len(steps))
	revAdj := make(map[string][]string, len(steps)) // dep → steps that depend on it
	for _, s := range steps {
		indeg[s.Name()] = len(s.Requires())
		for _, dep := range s.Requires() {
			revAdj[dep] = append(revAdj[dep], s.Name())
		}
	}

	out := make([]Step, 0, len(steps))
	emitted := make(map[string]bool, len(steps))

	// Loop: repeatedly scan `order` for any step whose in-degree is 0
	// and not yet emitted. This preserves stability.
	for len(out) < len(steps) {
		progress := false
		for _, name := range order {
			if emitted[name] {
				continue
			}
			if indeg[name] != 0 {
				continue
			}
			out = append(out, byName[name])
			emitted[name] = true
			progress = true
			for _, dependent := range revAdj[name] {
				indeg[dependent]--
			}
		}
		if !progress {
			// Cycle detected — gather the unemitted nodes for a clear
			// error message.
			cycle := make([]string, 0)
			for _, name := range order {
				if !emitted[name] {
					cycle = append(cycle, name)
				}
			}
			return nil, fmt.Errorf("saga.TopoSort: cycle detected among steps %s", strings.Join(cycle, ", "))
		}
	}

	return out, nil
}
