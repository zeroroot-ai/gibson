// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// belief_schema.go declares the belief-PRM SCHEMA SEAM between the ontology
// (this package, and taxonomy) and the belief substrate (internal/engine/brain,
// ADR-0129). It answers exactly two questions for the belief engine:
//
//  1. Which node types are belief-bearing, and what probabilistic variables
//     (and intra-node dependencies) does each one declare? (ADR-0129)
//  2. Which relationship types propagate belief — the enablement-edge flag?
//     (ADR-0129)
//
// This file does NOT instantiate a ground Bayesian attack graph, run
// inference, or discover new schema at runtime — that is #275/#276 (belief
// engine, owned by Lane B) and #274/#281 (ontology/taxonomy discovery and
// promotion) respectively. It only publishes the declarative schema those
// slices consume, plus the seed content that replaces today's hardcoded
// three-variable per-Host belief field (ADR-0129, internal/engine/brain).
//
// Registration follows the same named-extension, replace-on-name pattern as
// Reasoner.RegisterExtension (ADR-0124's discoverable-ontology seam), so a
// Domain Pack registers its belief schema the same way it registers taxonomy
// hierarchies: stage the merged view, validate it as a whole, then commit.
// The type does not reuse sdkgraphrag.OntologyExtension because the belief-PRM
// schema is Gibson-internal — never a customer-facing SDK contract.

// BeliefVariable declares one probabilistic variable a belief-bearing node
// type carries.
type BeliefVariable struct {
	// Name identifies the variable within its node type (e.g. "reachable").
	Name string

	// DependsOn lists the names of other variables on the SAME node type that
	// this variable's CPT is conditioned on. Cross-node dependencies are never
	// expressed here — they are wired by the belief engine along enablement
	// edges (see EnablementEdges) when it grounds the per-node template into
	// the attack graph.
	DependsOn []string
}

// NodeBeliefSchema is the belief-PRM schema for one node type: its declared
// variables and their intra-node dependencies (ADR-0129).
type NodeBeliefSchema struct {
	// NodeType is the taxonomy node type this schema applies to (e.g. "Host").
	// It must be a member of, or at least a well-formed identifier compatible
	// with, the taxonomy vocabulary this package's sibling (internal/engine/taxonomy)
	// governs — see ValidIdentifier.
	NodeType string

	// Variables is the node type's declared belief variables. Must be
	// non-empty: a NodeBeliefSchema with no variables is not belief-bearing
	// and should simply be omitted.
	Variables []BeliefVariable
}

// EnablementEdgeSpec declares one relationship type that propagates belief
// (ADR-0129) and the STRUCTURE of that propagation (ADR-0137):
// "an edge of RelType feeds TargetVariable on its destination node" — the
// node at the edge's To end, direction taken verbatim from the infra graph
// the same way DeriveAttackGraph already does, so no separate direction
// field is needed.
//
// This is declarative structure only, authored like the rest of the
// ontology. The noisy-OR STRENGTH that contribution carries is never
// declared here: ADR-0137 makes it a learned Beta posterior, fit
// offline by braintrain from recorded outcomes (#395), consumed as the
// posterior mean; until a posterior exists, the belief runtime grounds this
// edge type at the uninformative-prior mean instead (ADR-0137,
// internal/engine/brain's UninformativePriorStrength) — never a
// hand-authored number.
type EnablementEdgeSpec struct {
	// RelType is the relationship type this spec flags as belief-propagating
	// (e.g. "RESOLVES_TO").
	RelType string

	// TargetVariable names the belief variable this edge type feeds on its
	// destination node — a BeliefVariable.Name the destination node's OWN
	// NodeBeliefSchema declares, though that is validated at grounding time
	// (which concrete node types an edge type ever points at is graph data,
	// not schema), not at registration time.
	TargetVariable string
}

// BeliefSchemaExtension is a named, Pack-contributed bundle of belief-bearing
// node declarations and enablement-edge flags (ADR-0124 / ADR-0129).
// Register it with a BeliefSchemaRegistry the same way an
// sdkgraphrag.OntologyExtension is registered with a Reasoner.
type BeliefSchemaExtension struct {
	// Nodes lists the belief-bearing node type declarations this extension
	// contributes.
	Nodes []NodeBeliefSchema

	// EnablementEdges lists relationship types that propagate belief along
	// them, and which target variable each feeds (ADR-0129, ADR-0137).
	// Order is insignificant; two extensions (or one extension,
	// twice) declaring the SAME RelType with the SAME TargetVariable is
	// benign and unioned; declaring it with a DIFFERENT TargetVariable is a
	// hard conflict (see BeliefSchemaRegistry.RegisterExtension).
	EnablementEdges []EnablementEdgeSpec
}

// DuplicateVariableError is returned by RegisterExtension when two
// extensions (or one extension, twice) declare the same variable name for
// the same node type. Unlike enablement-edge flags, there is no way to
// reconcile two competing variable declarations, so this is a hard error
// rather than a silent merge.
type DuplicateVariableError struct {
	NodeType string
	Variable string
}

func (e *DuplicateVariableError) Error() string {
	return fmt.Sprintf("ontology: belief variable %q already declared for node type %q", e.Variable, e.NodeType)
}

// UnknownVariableDependencyError is returned by RegisterExtension when a
// BeliefVariable.DependsOn entry does not name another variable declared on
// the same node type.
type UnknownVariableDependencyError struct {
	NodeType  string
	Variable  string
	DependsOn string
}

func (e *UnknownVariableDependencyError) Error() string {
	return fmt.Sprintf("ontology: belief variable %q on node type %q depends on unknown variable %q "+
		"(cross-node dependencies are expressed via enablement edges, not DependsOn)",
		e.Variable, e.NodeType, e.DependsOn)
}

// VariableCycleError is returned by RegisterExtension when a node type's
// variable dependencies form a cycle, which would make its CPT unsolvable.
type VariableCycleError struct {
	NodeType string
	Cycle    []string
}

func (e *VariableCycleError) Error() string {
	return fmt.Sprintf("ontology: belief variable cycle on node type %q: %v", e.NodeType, e.Cycle)
}

// ConflictingEnablementEdgeTargetError is returned by RegisterExtension when
// two extensions (or one extension, twice) declare the SAME enablement edge
// RelType with DIFFERENT TargetVariable values (ADR-0137). Unlike
// the plain enablement-edge flag, a target variable is a payload, not just a
// flag, so two competing declarations cannot be silently unioned.
type ConflictingEnablementEdgeTargetError struct {
	RelType  string
	Existing string
	New      string
}

func (e *ConflictingEnablementEdgeTargetError) Error() string {
	return fmt.Sprintf(
		"ontology: enablement edge %q already targets variable %q, cannot also target %q",
		e.RelType, e.Existing, e.New,
	)
}

// BeliefSchemaRegistry holds the belief-PRM schema declared by the
// ontology/Pack: which node types are belief-bearing, their variables and
// intra-node dependencies, and which relationship types are enablement
// edges. Thread safety: all public methods are safe for concurrent use.
type BeliefSchemaRegistry struct {
	mu sync.RWMutex

	// extensions tracks which IRIs/declarations were contributed by which
	// named extension, so Unregister can rebuild from the remainder — the
	// same pattern as Reasoner.extensions.
	extensions map[string]BeliefSchemaExtension

	// nodes is the merged, live view: node type -> variable name -> variable.
	// A nested map keeps variable lookup and duplicate detection O(1).
	nodes map[string]map[string]BeliefVariable

	// enablementEdges is the merged, live view: relationship type -> the
	// target variable it feeds (ADR-0137).
	enablementEdges map[string]string
}

// NewBeliefSchemaRegistry constructs an empty registry. Register the core
// seed with RegisterCoreBeliefSchemaSeed, then let Domain Packs extend it via
// RegisterExtension.
func NewBeliefSchemaRegistry() *BeliefSchemaRegistry {
	return &BeliefSchemaRegistry{
		extensions:      make(map[string]BeliefSchemaExtension),
		nodes:           make(map[string]map[string]BeliefVariable),
		enablementEdges: make(map[string]string),
	}
}

// RegisterExtension adds the belief schema declarations from ext under the
// given name. If an extension with that name is already registered, the old
// one is replaced.
//
// Validation runs against the FULL merged view (all currently registered
// extensions plus ext), staged before anything is committed, mirroring
// Reasoner.RegisterExtension:
//   - Every node type and enablement edge type must be a well-formed
//     taxonomy identifier (ValidIdentifier).
//   - A NodeBeliefSchema must declare at least one variable.
//   - Variable names must be unique within a node type, across ALL
//     extensions (DuplicateVariableError) — first-registered wins the slot;
//     a conflicting later registration is rejected outright, not merged.
//   - DependsOn must name another variable already declared on the SAME node
//     type, in the merged view (UnknownVariableDependencyError).
//   - A node type's DependsOn graph must be acyclic (VariableCycleError).
//   - Enablement edge types may repeat across extensions with no conflict —
//     it is a flag, not a payload — and are unioned.
//
// On any validation error, ext is not applied and the registry is unchanged.
func (r *BeliefSchemaRegistry) RegisterExtension(name string, ext BeliefSchemaExtension) error {
	if err := validateBeliefSchemaExtensionShape(ext); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	staged := make(map[string]BeliefSchemaExtension, len(r.extensions)+1)
	maps.Copy(staged, r.extensions)
	staged[name] = ext

	nodes, enablementEdges, err := mergeBeliefSchemaExtensions(staged)
	if err != nil {
		return err
	}

	r.extensions[name] = ext
	r.nodes = nodes
	r.enablementEdges = enablementEdges
	return nil
}

// UnregisterExtension removes the named extension and rebuilds the merged
// view from the remainder. It is a no-op if the extension is not registered.
// Rebuilding from the remainder cannot fail validation, because the
// remainder was valid before ext was layered on top of it.
func (r *BeliefSchemaRegistry) UnregisterExtension(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.extensions[name]; !ok {
		return nil
	}
	delete(r.extensions, name)

	nodes, enablementEdges, err := mergeBeliefSchemaExtensions(r.extensions)
	if err != nil {
		// Unreachable in practice (see doc comment), but fail loud rather
		// than serve a partially-rebuilt view.
		return fmt.Errorf("ontology: rebuild after unregistering %q: %w", name, err)
	}
	r.nodes = nodes
	r.enablementEdges = enablementEdges
	return nil
}

// --- Read API (consumed by the belief engine, gibson#276) ---

// IsBeliefBearing reports whether nodeType has a declared belief-PRM schema.
func (r *BeliefSchemaRegistry) IsBeliefBearing(nodeType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.nodes[nodeType]
	return ok
}

// Variables returns the belief variables declared for nodeType, in
// unspecified order. Returns nil if nodeType is not belief-bearing. The
// returned slice (and each BeliefVariable.DependsOn slice) is a defensive
// copy safe for the caller to mutate.
func (r *BeliefSchemaRegistry) Variables(nodeType string) []BeliefVariable {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byName := r.nodes[nodeType]
	if len(byName) == 0 {
		return nil
	}
	out := make([]BeliefVariable, 0, len(byName))
	for _, v := range byName {
		cp := BeliefVariable{Name: v.Name}
		if len(v.DependsOn) > 0 {
			cp.DependsOn = slices.Clone(v.DependsOn)
		}
		out = append(out, cp)
	}
	return out
}

// BeliefBearingNodeTypes returns every node type with a declared belief-PRM
// schema, sorted.
func (r *BeliefSchemaRegistry) BeliefBearingNodeTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := slices.Collect(maps.Keys(r.nodes))
	sort.Strings(out)
	return out
}

// IsEnablementEdge reports whether belief propagates along relType — the
// enablement-edge flag from ADR-0129.
func (r *BeliefSchemaRegistry) IsEnablementEdge(relType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.enablementEdges[relType]
	return ok
}

// EnablementEdgeTypes returns every relationship type flagged as
// belief-propagating, sorted.
func (r *BeliefSchemaRegistry) EnablementEdgeTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := slices.Collect(maps.Keys(r.enablementEdges))
	sort.Strings(out)
	return out
}

// EnablementEdgeTargetVariable returns the belief variable relType feeds on
// its destination node (ADR-0137), and whether relType is a known
// enablement edge at all (equivalent to IsEnablementEdge) — a TargetVariable
// is mandatory on every registered EnablementEdgeSpec (see
// validateBeliefSchemaExtensionShape), so ok is false only when relType was
// never flagged as belief-propagating in the first place; a registered edge
// type always has a target variable to report.
func (r *BeliefSchemaRegistry) EnablementEdgeTargetVariable(relType string) (variable string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	variable, ok = r.enablementEdges[relType]
	return variable, ok
}

// --- internal helpers ---

// validateBeliefSchemaExtensionShape checks the parts of ext that can be
// validated in isolation, before it is merged with anything else registered.
func validateBeliefSchemaExtensionShape(ext BeliefSchemaExtension) error {
	for _, n := range ext.Nodes {
		if err := taxonomy.ValidIdentifier(n.NodeType); err != nil {
			return fmt.Errorf("ontology: belief schema node type: %w", err)
		}
		if len(n.Variables) == 0 {
			return fmt.Errorf("ontology: belief schema node type %q declares no variables", n.NodeType)
		}
		seen := make(map[string]struct{}, len(n.Variables))
		for _, v := range n.Variables {
			if err := taxonomy.ValidIdentifier(v.Name); err != nil {
				return fmt.Errorf("ontology: belief variable name: %w", err)
			}
			if _, dup := seen[v.Name]; dup {
				return &DuplicateVariableError{NodeType: n.NodeType, Variable: v.Name}
			}
			seen[v.Name] = struct{}{}
			for _, dep := range v.DependsOn {
				if err := taxonomy.ValidIdentifier(dep); err != nil {
					return fmt.Errorf("ontology: belief variable dependency: %w", err)
				}
			}
		}
	}
	for _, edge := range ext.EnablementEdges {
		if err := taxonomy.ValidIdentifier(edge.RelType); err != nil {
			return fmt.Errorf("ontology: enablement edge type: %w", err)
		}
		if err := taxonomy.ValidIdentifier(edge.TargetVariable); err != nil {
			return fmt.Errorf("ontology: enablement edge %q target variable: %w", edge.RelType, err)
		}
	}
	return nil
}

// mergeBeliefSchemaExtensions merges every extension in exts into one
// consistent view, validating cross-extension invariants that
// validateBeliefSchemaExtensionShape cannot see in isolation: duplicate
// variable names across extensions, unknown DependsOn references, and
// per-node dependency cycles.
//
// Map iteration order over exts is non-deterministic, so any error returned
// must not depend on which extension happened to be visited first for a
// GIVEN conflict to be detected as a conflict — only which extension's name
// is blamed in the error may vary, and that is acceptable (the caller only
// distinguishes error vs. no error; message text is not part of the
// contract).
func mergeBeliefSchemaExtensions(exts map[string]BeliefSchemaExtension) (nodes map[string]map[string]BeliefVariable, enablementEdges map[string]string, err error) {
	nodes = make(map[string]map[string]BeliefVariable)
	enablementEdges = make(map[string]string)

	for _, ext := range exts {
		for _, n := range ext.Nodes {
			byName, ok := nodes[n.NodeType]
			if !ok {
				byName = make(map[string]BeliefVariable, len(n.Variables))
				nodes[n.NodeType] = byName
			}
			for _, v := range n.Variables {
				if _, dup := byName[v.Name]; dup {
					return nil, nil, &DuplicateVariableError{NodeType: n.NodeType, Variable: v.Name}
				}
				byName[v.Name] = v
			}
		}
		for _, edge := range ext.EnablementEdges {
			if existing, ok := enablementEdges[edge.RelType]; ok && existing != edge.TargetVariable {
				return nil, nil, &ConflictingEnablementEdgeTargetError{
					RelType: edge.RelType, Existing: existing, New: edge.TargetVariable,
				}
			}
			enablementEdges[edge.RelType] = edge.TargetVariable
		}
	}

	for nodeType, byName := range nodes {
		for _, v := range byName {
			for _, dep := range v.DependsOn {
				if _, ok := byName[dep]; !ok {
					return nil, nil, &UnknownVariableDependencyError{
						NodeType: nodeType, Variable: v.Name, DependsOn: dep,
					}
				}
			}
		}
		if cycle := detectVariableCycle(byName); cycle != nil {
			return nil, nil, &VariableCycleError{NodeType: nodeType, Cycle: cycle}
		}
	}

	return nodes, enablementEdges, nil
}

// detectVariableCycle returns a representative cycle path through the
// DependsOn graph of byName, or nil if it is a DAG. Mirrors the DFS
// three-colour cycle detector in reasoner.go's detectCycle, specialised to
// the variable-dependency shape.
func detectVariableCycle(byName map[string]BeliefVariable) []string {
	const (
		unvisited = 0
		inStack   = 1
		done      = 2
	)
	state := make(map[string]int, len(byName))
	var path []string
	var found []string

	var dfs func(name string) bool
	dfs = func(name string) bool {
		state[name] = inStack
		path = append(path, name)
		for _, dep := range byName[name].DependsOn {
			if state[dep] == inStack {
				for i, p := range path {
					if p == dep {
						found = append([]string(nil), path[i:]...)
						return true
					}
				}
				found = []string{dep}
				return true
			}
			if state[dep] == unvisited {
				if dfs(dep) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		state[name] = done
		return false
	}

	// Deterministic iteration order so the SAME cycle is reported the same
	// way regardless of Go's map iteration randomisation.
	names := slices.Collect(maps.Keys(byName))
	sort.Strings(names)
	for _, name := range names {
		if state[name] == unvisited {
			if dfs(name) {
				return found
			}
		}
	}
	return nil
}
