// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — mission_projection.go
//
// missionDefinitionToProjected translates a CUE-authored gibson.mission.v1
// MissionDefinition into the brain-native brain.MissionProjected launch event
// (gibson#844). The brain stays proto-free (like the observation ingest path),
// so this proto→brain seam lives here. CUE declares dependencies, not a schedule:
// each node's deps are the union of its `dependencies` field and the incoming
// `edges`; the brain's Scheduler turns that into deterministic deferred ordering.
//
// Control-flow nodes collapse here (gibson#846): `parallel`/`join` evaporate into
// pure DependsOn topology (no dedicated entity), while `condition` survives as a
// kind="condition" WorkItem carrying its CEL spec, gating its branch nodes — the
// brain's ConditionSystem resolves it deterministically.
//
// This is the projection itself; wiring it onto live mission launch is the
// wholesale cutover (gibson#851).
package daemon

import (
	"encoding/json"
	"fmt"
	"google.golang.org/protobuf/encoding/protojson"
	"sort"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// missionDefinitionToProjected builds the launch event for a scripted mission.
// goal is the mission objective for the Decider (empty for a no-goal mission that
// runs its script deterministically and stops); it is supplied by the caller
// (dispatch request / mission metadata), not carried in the definition.
func missionDefinitionToProjected(def *missionpb.MissionDefinition, goal string) (brain.MissionProjected, error) {
	if def == nil {
		return brain.MissionProjected{}, fmt.Errorf("nil mission definition")
	}

	// 1. Flatten parallel sub-nodes into the node set (they become real nodes).
	allNodes := map[string]*missionpb.MissionNode{}
	for id, n := range def.GetNodes() {
		allNodes[id] = n
	}
	for id, n := range def.GetNodes() {
		if n.GetType() == missionpb.NodeType_NODE_TYPE_PARALLEL {
			for _, sub := range n.GetParallelConfig().GetSubNodes() {
				if sub.GetId() == "" {
					return brain.MissionProjected{}, fmt.Errorf("parallel node %q: sub-node missing id", id)
				}
				allNodes[sub.GetId()] = sub
			}
		}
	}

	// 2. Raw deps: per-node `dependencies` ∪ incoming `edges`. Parallel sub-nodes
	// inherit the parallel node's deps.
	deps := map[string]map[string]struct{}{}
	addDep := func(node, on string) {
		if node == on || on == "" {
			return
		}
		if deps[node] == nil {
			deps[node] = map[string]struct{}{}
		}
		deps[node][on] = struct{}{}
	}
	for id, n := range allNodes {
		for _, d := range n.GetDependencies() {
			addDep(id, d)
		}
	}
	for _, e := range def.GetEdges() {
		addDep(e.GetTo(), e.GetFrom())
	}
	for id, n := range def.GetNodes() {
		if n.GetType() == missionpb.NodeType_NODE_TYPE_PARALLEL {
			for _, sub := range n.GetParallelConfig().GetSubNodes() {
				for d := range deps[id] {
					addDep(sub.GetId(), d)
				}
			}
		}
	}

	// 3. condition branch gating: every branch node depends on its condition node.
	for id, n := range allNodes {
		if n.GetType() == missionpb.NodeType_NODE_TYPE_CONDITION {
			for _, b := range append(append([]string{}, n.GetConditionConfig().GetTrueBranch()...), n.GetConditionConfig().GetFalseBranch()...) {
				addDep(b, id)
			}
		}
	}

	// 4. resolve(id) → the real (agent/tool/plugin/condition) node ids that a
	// dependency on `id` stands for. parallel → its sub-nodes; join → its wait_for.
	resolve := makeResolver(allNodes)

	// 5. Build WorkNodes for real nodes, rewriting deps through resolve.
	var nodes []brain.WorkNode
	for id, n := range allNodes {
		switch n.GetType() {
		case missionpb.NodeType_NODE_TYPE_PARALLEL, missionpb.NodeType_NODE_TYPE_JOIN:
			continue // collapsed into DependsOn; no entity
		}
		kind, target, input, err := nodeKindTargetInput(n)
		if err != nil {
			return brain.MissionProjected{}, fmt.Errorf("node %q: %w", id, err)
		}
		resolved := map[string]struct{}{}
		for d := range deps[id] {
			for _, r := range resolve(d) {
				if r != id {
					resolved[r] = struct{}{}
				}
			}
		}
		nodes = append(nodes, brain.WorkNode{
			ID:         id,
			Kind:       kind,
			Target:     target,
			Input:      input,
			DependsOn:  sortedKeys(resolved),
			MaxRetries: int(n.GetRetryPolicy().GetMaxRetries()),
			Timeout:    nodeTimeout(n),
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return brain.MissionProjected{
		ID:          def.GetId(),
		Goal:        goal,
		Budget:      budgetFromConstraints(def.GetConstraints()),
		Nodes:       nodes,
		DeciderSlot: deciderSlotFrom(def.GetDeciderSlot()),
	}, nil
}

// nodeTimeout reads MissionNode.timeout as a duration. It is the only place the
// node's own execution bound enters the brain, and it is deliberately permissive:
// an absent or non-positive duration returns zero, which every consumer reads as
// "the node declared no bound" rather than "expire at once" (gibson#1602).
func nodeTimeout(n *missionpb.MissionNode) time.Duration {
	d := n.GetTimeout()
	if d == nil {
		return 0
	}
	if v := d.AsDuration(); v > 0 {
		return v
	}
	return 0
}

// deciderSlotFrom maps the mission's optional decider_slot (gibson#850) into the
// brain-native form. Empty → the brain uses the tenant dashboard default.
func deciderSlotFrom(s *missionpb.LLMSlotConfig) brain.DeciderSlot {
	if s == nil {
		return brain.DeciderSlot{}
	}
	return brain.DeciderSlot{Provider: s.GetProvider(), Model: s.GetModel()}
}

// makeResolver returns resolve(id) → real node ids. parallel/join expand to their
// members (transitively); real nodes resolve to themselves. Cycles are guarded.
func makeResolver(all map[string]*missionpb.MissionNode) func(string) []string {
	var resolve func(string, map[string]bool) []string
	resolve = func(id string, seen map[string]bool) []string {
		if seen[id] {
			return nil
		}
		seen[id] = true
		n, ok := all[id]
		if !ok {
			return []string{id} // unknown id: treat as a literal dep
		}
		switch n.GetType() {
		case missionpb.NodeType_NODE_TYPE_PARALLEL:
			var out []string
			for _, sub := range n.GetParallelConfig().GetSubNodes() {
				out = append(out, resolve(sub.GetId(), seen)...)
			}
			return out
		case missionpb.NodeType_NODE_TYPE_JOIN:
			var out []string
			for _, w := range n.GetJoinConfig().GetWaitFor() {
				out = append(out, resolve(w, seen)...)
			}
			return out
		default:
			return []string{id}
		}
	}
	return func(id string) []string { return resolve(id, map[string]bool{}) }
}

func nodeKindTargetInput(n *missionpb.MissionNode) (kind, target, input string, err error) {
	switch n.GetType() {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		// The task goal IS the work; dropping it dispatched the agent with an
		// empty objective and left the LLM to invent one (gibson#1196).
		return "agent", n.GetAgentConfig().GetAgentName(), n.GetAgentConfig().GetTask().GetGoal(), nil
	case missionpb.NodeType_NODE_TYPE_TOOL:
		// The node's input is the tool's parameters. It is carried as JSON because
		// that is the tool contract's own encoding (ExecuteRequest.input_json), so
		// the dispatcher passes it through without needing the tool's schema.
		in, mErr := toolInputJSON(n.GetToolConfig().GetInput())
		if mErr != nil {
			return "", "", "", mErr
		}
		return "tool", n.GetToolConfig().GetToolName(), in, nil
	case missionpb.NodeType_NODE_TYPE_PLUGIN:
		return "plugin", n.GetPluginConfig().GetPluginName(), n.GetPluginConfig().GetMethod(), nil
	case missionpb.NodeType_NODE_TYPE_JOB:
		// The bank is the target and the whole node config is the input, as
		// protojson, so the job node executor reads the spec and the bounds
		// without a second lookup (ADR-0019, gibson#1713).
		cfg := n.GetJobConfig()
		if cfg.GetBankRef() == "" {
			return "", "", "", fmt.Errorf("job node %s names no bank", n.GetId())
		}
		if cfg.GetSpec().GetGoal() == "" {
			return "", "", "", fmt.Errorf("job node %s has no goal", n.GetId())
		}
		b, mErr := protojson.Marshal(cfg)
		if mErr != nil {
			return "", "", "", fmt.Errorf("marshal job node config: %w", mErr)
		}
		return "job", cfg.GetBankRef(), string(b), nil
	case missionpb.NodeType_NODE_TYPE_CONDITION:
		c := n.GetConditionConfig()
		spec := brain.ConditionSpec{
			Expression:  c.GetExpression(),
			TrueBranch:  c.GetTrueBranch(),
			FalseBranch: c.GetFalseBranch(),
		}
		b, mErr := json.Marshal(spec)
		if mErr != nil {
			return "", "", "", fmt.Errorf("marshal condition spec: %w", mErr)
		}
		return "condition", "", string(b), nil
	default:
		return "", "", "", fmt.Errorf("unsupported node type %s", n.GetType())
	}
}

func budgetFromConstraints(c *missionpb.MissionConstraints) brain.Budget {
	if c == nil {
		return brain.Budget{}
	}
	// MaxExecutions (the runaway cap) has no proto field yet — gibson#849 sources
	// it. MaxTokens maps directly to the cumulative mission token budget.
	return brain.Budget{MaxTokens: c.GetMaxTokens()}
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// toolInputJSON encodes a tool node's declared input as the JSON object the tool
// contract expects.
//
// Empty input encodes to the empty string rather than "{}": a tool that takes no
// parameters and a tool whose parameters were lost should not look identical on
// the wire, and the tool side already reads an absent input_json as "no
// parameters". Keys are emitted sorted by encoding/json, so the same node always
// projects to the same bytes — projection feeds a replayable event log.
func toolInputJSON(in map[string]string) (string, error) {
	if len(in) == 0 {
		return "", nil
	}
	// MissionNode.tool_config.input is map<string,string>, but a tool contract
	// is plain JSON and plenty of parameters are not strings: nmap's `args` is
	// []string, and marshalling the map verbatim handed the tool
	// {"args":"-sV -vv"} where it required ["-sV","-vv"]. The tool rejected the
	// input, the sandbox exited 1, and the node failed for a reason no mission
	// author could see from the schema.
	//
	// A value that STARTS with [ or { and parses is embedded as the JSON it
	// already is; everything else stays a string. The leading-bracket test is
	// what keeps "80" a string rather than the number 80, which would break
	// every tool reading it out of the string-typed Options map.
	fields := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		if t := strings.TrimSpace(v); strings.HasPrefix(t, "[") || strings.HasPrefix(t, "{") {
			if json.Valid([]byte(t)) {
				fields[k] = json.RawMessage(t)
				continue
			}
		}
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("marshal tool input %q: %w", k, err)
		}
		fields[k] = json.RawMessage(b)
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("marshal tool input: %w", err)
	}
	return string(b), nil
}
