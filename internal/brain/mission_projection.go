package brain

// WorkNode is one node of a CUE mission's work-graph, in brain-native form (the
// daemon translates a gibson.mission.v1.MissionDefinition into these — the brain
// stays proto-free, like the observation ingest path). Edges are carried as each
// node's DependsOn; CUE `parallel`/`join` collapse into DependsOn topology and
// need no node kind here (gibson#846), so Kind is one of "agent"|"tool"|"plugin"
// (plus "condition" once gibson#846 lands).
type WorkNode struct {
	ID        string
	Kind      string
	Target    string   // capability name (agent/tool/plugin)
	Input     string   // opaque dispatch input (the node config), carried for dispatch
	DependsOn []string // node IDs this one depends on
}

// MissionProjected is the launch event for a scripted CUE mission (ADR-0001): the
// mission definition projected into the World. The reducer seeds the Mission
// (goal + budget) and one `pending` WorkItem per node, wired with DependsOn. A
// mission with an empty Goal is a no-goal mission — it runs deterministically to
// quiescence with the Decider never firing (CONTEXT.md). Distinct from the
// minimal MissionStarted, which only seeds an observed mission.
type MissionProjected struct {
	ID     string
	Goal   string
	Budget Budget
	Nodes  []WorkNode
}

func (MissionProjected) Kind() string { return "mission.projected" }

func applyMissionProjected(w *World, e MissionProjected) {
	if _, ok := findMission(w, e.ID); ok {
		return // idempotent: already projected
	}
	w.missions.NewEntity(&Mission{ID: e.ID, Goal: e.Goal, Status: MissionRunning, Budget: e.Budget})
	for _, n := range e.Nodes {
		if _, ok := findWork(w, n.ID); ok {
			continue // idempotent
		}
		w.work.NewEntity(&WorkItem{
			ID:        n.ID,
			MissionID: e.ID,
			Kind:      n.Kind,
			Target:    n.Target,
			Input:     n.Input,
			DependsOn: append([]string(nil), n.DependsOn...),
			State:     WorkPending,
		})
	}
}
