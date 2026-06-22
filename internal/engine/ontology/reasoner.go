// Package ontology implements the in-process ontology reasoner for the Gibson
// daemon. It loads vocabulary from the embedded SDK ontology at startup and
// supports dynamic extension registration for tenant-supplied or plugin-supplied
// ontology files.
//
// The Reasoner struct implements sdk/graphrag.Reasoner. A single shared instance
// is wired into the daemon at startup and injected into the graphrag service
// layer for IRI expansion at query time.
//
// Thread safety: all public methods are safe for concurrent use.
package ontology

import (
	"errors"
	"fmt"
	"sync"

	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// CycleError is returned by RegisterExtension when the new triples would
// introduce a cycle in the subClassOf hierarchy.
type CycleError struct {
	// Cycle lists the IRIs that form the detected cycle.
	Cycle []string
}

func (e *CycleError) Error() string {
	return fmt.Sprintf("ontology: subClassOf cycle detected: %v", e.Cycle)
}

// UnknownPrefixError is returned by RegisterExtension when a hierarchy entry
// or equivalence pair references a prefix not declared in the extension's
// prefix map.
type UnknownPrefixError struct {
	IRI    string
	Prefix string
}

func (e *UnknownPrefixError) Error() string {
	return fmt.Sprintf("ontology: unknown prefix %q in IRI %q", e.Prefix, e.IRI)
}

// Reasoner is the in-process ontology engine. Load the core SDK vocab via
// NewReasoner, then use RegisterExtension/UnregisterExtension for runtime
// additions.
//
// Implements sdk/graphrag.Reasoner.
type Reasoner struct {
	mu sync.RWMutex

	// parents maps IRI → set of direct parent IRIs (subClassOf edges).
	// The graph is stored as a forward-edge map for ancestor traversal.
	parents map[string]map[string]struct{}

	// children maps IRI → set of direct child IRIs (inverse of parents).
	children map[string]map[string]struct{}

	// sameAs maps IRI → set of equivalent IRIs (undirected, transitive closure stored
	// as a union-find representative is NOT used — we store full symmetric
	// expansion to keep query-time O(1) for small vocabs).
	sameAs map[string]map[string]struct{}

	// ifps maps nodeType → []propertyName
	ifps map[string][]string

	// extensions tracks which IRIs were contributed by which named extension.
	// On unregister, we rebuild from the remaining extensions.
	extensions map[string]sdkgraphrag.OntologyExtension

	// ancestorCache and descendantCache cache the transitive closures.
	// Rebuilt synchronously after each extension change.
	ancestorCache   map[string][]string
	descendantCache map[string][]string
	sameAsCache     map[string][]string

	metrics *Metrics
}

// NewReasoner constructs an empty Reasoner. Call Loader.LoadCore to populate
// it with the embedded SDK vocabulary.
func NewReasoner(metrics *Metrics) *Reasoner {
	if metrics == nil {
		metrics = NewMetrics()
	}
	return &Reasoner{
		parents:         make(map[string]map[string]struct{}),
		children:        make(map[string]map[string]struct{}),
		sameAs:          make(map[string]map[string]struct{}),
		ifps:            make(map[string][]string),
		extensions:      make(map[string]sdkgraphrag.OntologyExtension),
		ancestorCache:   make(map[string][]string),
		descendantCache: make(map[string][]string),
		sameAsCache:     make(map[string][]string),
		metrics:         metrics,
	}
}

// RegisterExtension adds the triples from ext under the given name. If an
// extension with that name is already registered the old one is replaced.
//
// Validation:
//   - All IRI prefix:localname tokens must have their prefix declared in
//     ext.Prefixes. Unknown prefixes → UnknownPrefixError.
//   - After merging the new triples, cycle detection runs on the subClassOf
//     graph. A cycle → CycleError; the extension is not applied.
//   - Benign duplicate triples (same parent already asserted) are accepted
//     (first-wins semantics — existing edge is kept, no error).
func (r *Reasoner) RegisterExtension(name string, ext sdkgraphrag.OntologyExtension) error {
	// Validate prefixes before acquiring the write lock.
	if err := validateExtensionPrefixes(ext); err != nil {
		r.metrics.RegistrationFailures.WithLabelValues("unknown_prefix").Inc()
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Stage the merged graph to detect cycles before mutating live state.
	staged := r.cloneGraph()
	applyExtension(staged, ext)

	if cycle := detectCycle(staged.parents); cycle != nil {
		r.metrics.RegistrationFailures.WithLabelValues("cycle").Inc()
		return &CycleError{Cycle: cycle}
	}

	// Commit: store the extension and rebuild the live graph from scratch.
	r.extensions[name] = ext
	r.rebuildLocked()

	r.metrics.ExtensionsLoaded.WithLabelValues(name).Set(1)
	r.metrics.IRIsTotal.Set(float64(len(r.parents)))
	return nil
}

// UnregisterExtension removes the named extension and rebuilds all caches.
// It is a no-op if the extension is not registered.
func (r *Reasoner) UnregisterExtension(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.extensions[name]; !ok {
		return nil
	}
	delete(r.extensions, name)
	r.rebuildLocked()

	r.metrics.ExtensionsLoaded.WithLabelValues(name).Set(0)
	r.metrics.IRIsTotal.Set(float64(len(r.parents)))
	return nil
}

// --- sdk/graphrag.Reasoner implementation ---

// Ancestors returns all transitive parent IRIs of iri, ordered from closest
// to farthest ancestor. Returns an empty slice for unknown IRIs.
func (r *Reasoner) Ancestors(iri string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := r.ancestorCache[iri]
	if out == nil {
		return []string{}
	}
	cp := make([]string, len(out))
	copy(cp, out)
	return cp
}

// Descendants returns all transitive child IRIs of iri. Returns an empty
// slice for leaf or unknown IRIs.
func (r *Reasoner) Descendants(iri string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := r.descendantCache[iri]
	if out == nil {
		return []string{}
	}
	cp := make([]string, len(out))
	copy(cp, out)
	return cp
}

// Equivalents returns all IRIs equivalent to iri via sameAs (transitively).
// The input IRI is not included. Returns an empty slice if unknown.
func (r *Reasoner) Equivalents(iri string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := r.sameAsCache[iri]
	if out == nil {
		return []string{}
	}
	cp := make([]string, len(out))
	copy(cp, out)
	return cp
}

// IsSubclassOf reports whether child is a (direct or transitive) subclass of
// parent. Returns false if either IRI is unknown.
func (r *Reasoner) IsSubclassOf(child, parent string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.ancestorCache[child] {
		if a == parent {
			return true
		}
	}
	// Also check direct parent set for nodes not yet in the cache.
	if ps, ok := r.parents[child]; ok {
		if _, direct := ps[parent]; direct {
			return true
		}
	}
	return false
}

// IFPsForType returns the inverse-functional property names for nodeType.
func (r *Reasoner) IFPsForType(nodeType string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	props := r.ifps[nodeType]
	if props == nil {
		return []string{}
	}
	cp := make([]string, len(props))
	copy(cp, props)
	return cp
}

// --- internal helpers ---

// stagedGraph is a snapshot of the hierarchy graph used for cycle detection.
type stagedGraph struct {
	parents  map[string]map[string]struct{}
	children map[string]map[string]struct{}
}

func (r *Reasoner) cloneGraph() *stagedGraph {
	g := &stagedGraph{
		parents:  make(map[string]map[string]struct{}, len(r.parents)),
		children: make(map[string]map[string]struct{}, len(r.children)),
	}
	for k, v := range r.parents {
		cp := make(map[string]struct{}, len(v))
		for p := range v {
			cp[p] = struct{}{}
		}
		g.parents[k] = cp
	}
	for k, v := range r.children {
		cp := make(map[string]struct{}, len(v))
		for c := range v {
			cp[c] = struct{}{}
		}
		g.children[k] = cp
	}
	return g
}

// applyExtension adds the hierarchy triples from ext into the staged graph.
// Duplicate edges are silently ignored (first-wins).
func applyExtension(g *stagedGraph, ext sdkgraphrag.OntologyExtension) {
	for _, h := range ext.Hierarchies {
		if h.Label == "" {
			continue
		}
		// Ensure node is known even if it has no parent.
		if _, ok := g.parents[h.Label]; !ok {
			g.parents[h.Label] = make(map[string]struct{})
		}
		if _, ok := g.children[h.Label]; !ok {
			g.children[h.Label] = make(map[string]struct{})
		}
		if h.SubClassOf == "" {
			continue
		}
		// Ensure parent node is known.
		if _, ok := g.parents[h.SubClassOf]; !ok {
			g.parents[h.SubClassOf] = make(map[string]struct{})
		}
		if _, ok := g.children[h.SubClassOf]; !ok {
			g.children[h.SubClassOf] = make(map[string]struct{})
		}
		// First-wins: skip if already present.
		if _, exists := g.parents[h.Label][h.SubClassOf]; exists {
			continue
		}
		g.parents[h.Label][h.SubClassOf] = struct{}{}
		g.children[h.SubClassOf][h.Label] = struct{}{}
	}
}

// rebuildLocked rebuilds the live graph from all registered extensions and
// recomputes transitive caches. Must be called with r.mu held for writing.
func (r *Reasoner) rebuildLocked() {
	timer := r.metrics.ClosureRebuildDuration.Start()

	r.parents = make(map[string]map[string]struct{})
	r.children = make(map[string]map[string]struct{})
	r.sameAs = make(map[string]map[string]struct{})
	r.ifps = make(map[string][]string)

	g := &stagedGraph{parents: r.parents, children: r.children}
	for _, ext := range r.extensions {
		applyExtension(g, ext)

		// Merge sameAs pairs.
		for _, pair := range ext.Equivalences {
			a, b := pair[0], pair[1]
			if r.sameAs[a] == nil {
				r.sameAs[a] = make(map[string]struct{})
			}
			if r.sameAs[b] == nil {
				r.sameAs[b] = make(map[string]struct{})
			}
			r.sameAs[a][b] = struct{}{}
			r.sameAs[b][a] = struct{}{}
		}

		// Merge IFPs (deduplicate per nodeType).
		for _, ifp := range ext.IFPs {
			existing := r.ifps[ifp.NodeType]
			seen := make(map[string]struct{}, len(existing))
			for _, p := range existing {
				seen[p] = struct{}{}
			}
			if _, dup := seen[ifp.Property]; !dup {
				r.ifps[ifp.NodeType] = append(r.ifps[ifp.NodeType], ifp.Property)
			}
		}
	}

	// Compute transitive closures.
	r.ancestorCache = computeAncestors(r.parents)
	r.descendantCache = computeDescendants(r.children)
	r.sameAsCache = computeSameAsTransitive(r.sameAs)

	timer()
}

// detectCycle returns a representative cycle path if the parents graph
// contains any cycle, or nil if the graph is a DAG.
func detectCycle(parents map[string]map[string]struct{}) []string {
	const (
		unvisited = 0
		inStack   = 1
		done      = 2
	)
	state := make(map[string]int, len(parents))
	var path []string
	var found []string

	var dfs func(node string) bool
	dfs = func(node string) bool {
		state[node] = inStack
		path = append(path, node)
		for parent := range parents[node] {
			if state[parent] == inStack {
				// Collect the cycle portion.
				for i, p := range path {
					if p == parent {
						found = make([]string, len(path)-i)
						copy(found, path[i:])
						return true
					}
				}
				found = []string{parent}
				return true
			}
			if state[parent] == unvisited {
				if dfs(parent) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		state[node] = done
		return false
	}

	for node := range parents {
		if state[node] == unvisited {
			if dfs(node) {
				return found
			}
		}
	}
	return nil
}

// validateExtensionPrefixes checks that every prefix:localname IRI in ext
// has its prefix declared in ext.Prefixes.
func validateExtensionPrefixes(ext sdkgraphrag.OntologyExtension) error {
	check := func(iri string) error {
		if iri == "" {
			return nil
		}
		idx := indexByte(iri, ':')
		if idx <= 0 {
			// Not a prefixed IRI — skip validation.
			return nil
		}
		prefix := iri[:idx]
		if _, ok := ext.Prefixes[prefix]; !ok {
			return &UnknownPrefixError{IRI: iri, Prefix: prefix}
		}
		return nil
	}
	for _, h := range ext.Hierarchies {
		if err := check(h.Label); err != nil {
			return err
		}
		if err := check(h.SubClassOf); err != nil {
			return err
		}
	}
	for _, pair := range ext.Equivalences {
		if err := check(pair[0]); err != nil {
			return err
		}
		if err := check(pair[1]); err != nil {
			return err
		}
	}
	return nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// Ensure Reasoner satisfies the SDK interface at compile time.
var _ sdkgraphrag.Reasoner = (*Reasoner)(nil)

// Ensure CycleError and UnknownPrefixError satisfy the error interface.
var _ error = (*CycleError)(nil)
var _ error = (*UnknownPrefixError)(nil)

// isCycleError reports whether err is a CycleError. Used in tests.
func isCycleError(err error) bool {
	var ce *CycleError
	return errors.As(err, &ce)
}

// isUnknownPrefixError reports whether err is an UnknownPrefixError.
func isUnknownPrefixError(err error) bool {
	var upe *UnknownPrefixError
	return errors.As(err, &upe)
}
