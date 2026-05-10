package orchestrator

import (
	"context"
	"fmt"
	"sync"

	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// NodeHandler is the executor contract for a mission node. Each
// per-noun package under internal/orchestrator/nodes/ registers a
// handler at its package init() via RegisterNodeHandler. The
// orchestrator's act path resolves the handler from the registry
// and invokes it.
//
// Spec: mission-verb-noun-registry Requirement 2.
type NodeHandler func(ctx context.Context, node *missionv1.MissionNode, params HandlerParams) (*ActionResult, error)

// HandlerParams carries the cross-cutting orchestrator state a
// node executor needs. Kept deliberately minimal — fields are
// added only when a handler proves a need. See spec design.md
// Component 1.
type HandlerParams struct {
	// MissionID is the in-flight mission's ID.
	MissionID string

	// Definition is the mission's parsed definition. Handlers may
	// inspect dependencies, sibling nodes, etc. Read-only.
	Definition *missionv1.MissionDefinition

	// PriorResults maps node ID → previously-completed result.
	// Handlers read this to access upstream output (e.g. JOIN
	// reading wait_for sources, CONDITION reading the value
	// referenced in its expression). Implementations must not
	// mutate the map.
	PriorResults map[string]*ActionResult
}

// nodeRegistry is the package-level registry. Populated at
// package init() by per-noun packages calling RegisterNodeHandler.
// Reads and writes are mutex-guarded so init-order races (which
// would be a programming error, but might occur during refactors)
// surface predictably.
var (
	registryMu   sync.RWMutex
	nodeRegistry = make(map[missionv1.NodeType]NodeHandler)
)

// RegisterNodeHandler associates a NodeHandler with the given
// NodeType. Panics on duplicate registration — the registry is a
// build-time invariant, not a runtime state.
//
// Called at package init() by each per-noun package.
func RegisterNodeHandler(nt missionv1.NodeType, h NodeHandler) {
	if nt == missionv1.NodeType_NODE_TYPE_UNSPECIFIED {
		panic("node handler registered for NODE_TYPE_UNSPECIFIED")
	}
	if h == nil {
		panic(fmt.Sprintf("node handler for %s is nil", nt))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := nodeRegistry[nt]; exists {
		panic(fmt.Sprintf("node handler already registered for %s", nt))
	}
	nodeRegistry[nt] = h
}

// ResolveNodeHandler returns the registered handler for nt and a
// found flag. The found flag is false for UNSPECIFIED or for
// node types the daemon doesn't have a handler for. Callers
// should surface "not found" as codes.Unimplemented with the
// enum name.
func ResolveNodeHandler(nt missionv1.NodeType) (NodeHandler, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	h, ok := nodeRegistry[nt]
	return h, ok
}

// AssertNodeRegistryExhaustive panics if any non-UNSPECIFIED
// NodeType lacks a registered handler. Called from a coordinator
// package (internal/orchestrator/nodes/all) after every per-noun
// package has been imported and its init has run.
//
// This is the runtime backstop for the golangci-lint exhaustive
// check; the lint catches the regression at PR time, this catches
// it at startup if the lint is somehow bypassed.
func AssertNodeRegistryExhaustive() {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var missing []missionv1.NodeType
	for name, value := range missionv1.NodeType_value {
		if name == missionv1.NodeType_NODE_TYPE_UNSPECIFIED.String() {
			continue
		}
		nt := missionv1.NodeType(value)
		if _, ok := nodeRegistry[nt]; !ok {
			missing = append(missing, nt)
		}
	}
	if len(missing) > 0 {
		panic(fmt.Sprintf("node registry incomplete; missing handlers for: %v", missing))
	}
}

// resetNodeRegistryForTesting clears the registry. Used only by
// tests in this package. Not exported.
func resetNodeRegistryForTesting() {
	registryMu.Lock()
	defer registryMu.Unlock()
	nodeRegistry = make(map[missionv1.NodeType]NodeHandler)
}
