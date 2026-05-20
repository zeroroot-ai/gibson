package orchestrator

import (
	"context"
	"fmt"
	"sync"
)

// spawnCycleGuard tracks per-mission spawned-agent ancestry so
// spawn_agent can refuse cycles. The check is O(depth) in-memory
// and adds no graph DB calls or RPCs.
//
// Tracking model: for each (missionID, spawned_node_id) we record
// the spawning agent name and the list of upstream node IDs the
// new node depends on. cycleDetected walks back from the
// proposed spawn's depends_on chain through this in-memory record
// looking for the same agent name.
//
// Spec: mission-verb-noun-registry Requirement 8.
type spawnCycleGuard struct {
	mu sync.RWMutex
	// mission → node → record
	missions map[string]map[string]spawnRecord
}

type spawnRecord struct {
	agentName string
	dependsOn []string
}

func newSpawnCycleGuard() *spawnCycleGuard {
	return &spawnCycleGuard{
		missions: make(map[string]map[string]spawnRecord),
	}
}

// recordSpawn registers a spawned node's agent name and depends_on
// chain so future cycle checks can walk through it.
func (g *spawnCycleGuard) recordSpawn(missionID, nodeID, agentName string, dependsOn []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.missions[missionID]; !ok {
		g.missions[missionID] = make(map[string]spawnRecord)
	}
	g.missions[missionID][nodeID] = spawnRecord{
		agentName: agentName,
		dependsOn: append([]string(nil), dependsOn...),
	}
}

// forgetMission drops a mission's tracking record once the
// mission completes. Bounded memory.
func (g *spawnCycleGuard) forgetMission(missionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.missions, missionID)
}

// cycleDetected returns the cycle path if spawning `agentName`
// with the given `dependsOn` chain would create a cycle. Returns
// nil if no cycle.
//
// Algorithm: BFS over previously-spawned nodes along the
// depends_on chain. If any visited node was spawned by the same
// agent, that's the cycle. Caps walk depth at maxDepth to bound
// pathological mission graphs.
func (g *spawnCycleGuard) cycleDetected(missionID, agentName string, dependsOn []string) []string {
	const maxDepth = 64
	g.mu.RLock()
	defer g.mu.RUnlock()
	missionRecs, ok := g.missions[missionID]
	if !ok {
		return nil
	}
	visited := make(map[string]bool, 16)
	frontier := append([]string(nil), dependsOn...)
	depth := 0
	for len(frontier) > 0 && depth < maxDepth {
		next := make([]string, 0, len(frontier))
		for _, id := range frontier {
			if visited[id] {
				continue
			}
			visited[id] = true
			rec, ok := missionRecs[id]
			if !ok {
				continue
			}
			if rec.agentName == agentName {
				path := append([]string(nil), dependsOn...)
				path = append(path, id)
				return path
			}
			next = append(next, rec.dependsOn...)
		}
		frontier = next
		depth++
	}
	return nil
}

// CycleError reports a detected spawn cycle.
type CycleError struct {
	AgentName string
	Path      []string
}

func (e *CycleError) Error() string {
	return fmt.Sprintf("spawn_agent: cycle detected — agent %q already in ancestor chain via %v", e.AgentName, e.Path)
}

// ensureNoCycle is the entry point spawn_agent calls before
// creating the new node. Returns a CycleError if the spawn would
// cycle; nil otherwise.
//
// Self-spawn (the new agent depends on a node spawned by itself
// at any depth) is the most common case the LLM produces and is
// caught here.
func (g *spawnCycleGuard) ensureNoCycle(_ context.Context, missionID, agentName string, dependsOn []string) error {
	if path := g.cycleDetected(missionID, agentName, dependsOn); path != nil {
		return &CycleError{AgentName: agentName, Path: path}
	}
	return nil
}
