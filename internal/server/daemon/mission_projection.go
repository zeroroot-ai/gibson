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
	"errors"
	"fmt"
	"google.golang.org/protobuf/encoding/protojson"
	"sort"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/mission/targetbind"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// missionDefinitionToProjected builds the launch event for a scripted mission.
// goal is the mission objective for the Decider (empty for a no-goal mission that
// runs its script deterministically and stops); it is supplied by the caller
// (dispatch request / mission metadata), not carried in the definition.
// targets is the mission run's resolved target set, primary first, as
// Mission.TargetSet() orders it. It is a RUN fact rather than a definition fact,
// which is why it is a parameter: the same definition fans out to two instances
// for a two-target run and one for a single-target run (gibson#525).
//
// An empty set is the pre-fan-out behaviour and is not an error — every mission
// before this took exactly one target and bound it at submit.
func missionDefinitionToProjected(
	def *missionpb.MissionDefinition,
	goal string,
	targets []forEachTarget,
) (brain.MissionProjected, fanOutOrigins, error) {
	if def == nil {
		return brain.MissionProjected{}, nil, errors.New("nil mission definition")
	}

	// 0. Refuse the fan-out declarations the daemon does not support, from the
	// same finder the mission-view analyser uses. This is on the run path on
	// purpose: a nested for_each that reached expansion would have its inner
	// for_each collapsed and never expanded, so the work it declares would
	// vanish without a word (gibson#527).
	if err := graph.RefuseUnsupportedFanOut(def.GetNodes()); err != nil {
		return brain.MissionProjected{}, nil, fmt.Errorf("mission %q: %w", def.GetId(), err)
	}

	// 1. Flatten parallel sub-nodes into the node set (they become real nodes).
	allNodes, err := flattenParallel(def)
	if err != nil {
		return brain.MissionProjected{}, nil, err
	}

	// 1b. Expand each for_each into one instance per target.
	forEachInstances, origins, err := expandForEachNodes(def, targets, allNodes)
	if err != nil {
		return brain.MissionProjected{}, nil, err
	}

	// 1c. A run that resolved more than one target but fans out over none would
	// bind every node to the primary and assess only that one, while the mission
	// record, the authorization scope and the report all say N.
	//
	// The originate path is the first to produce N>1: Originator.buildChild puts
	// req.TargetIDs[0] in TargetID and the rest in AdditionalTargetIDs. No submit
	// path does, which is why this could not fire before (gibson#529).
	if len(targets) > 1 && len(forEachInstances) == 0 {
		return brain.MissionProjected{}, nil, fmt.Errorf(
			"mission %q resolved %d targets but declares no for_each, so it would "+
				"assess only the first and report as though it covered all of them; "+
				"fan out with a for_each node, or run it against one target",
			def.GetId(), len(targets))
	}

	// 2. Raw deps: per-node `dependencies` ∪ incoming `edges`. Parallel sub-nodes
	// and for_each instances inherit their container node's deps.
	deps := nodeDeps{}
	for id, n := range allNodes {
		for _, d := range n.GetDependencies() {
			deps.add(id, d)
		}
	}
	for _, e := range def.GetEdges() {
		deps.add(e.GetTo(), e.GetFrom())
	}
	for id, n := range def.GetNodes() {
		if n.GetType() == missionpb.NodeType_NODE_TYPE_PARALLEL {
			for _, sub := range n.GetParallelConfig().GetSubNodes() {
				for d := range deps[id] {
					deps.add(sub.GetId(), d)
				}
			}
		}
	}
	boundFanOut(def, forEachInstances, deps)

	// 3. condition branch gating: every branch node depends on its condition node.
	for id, n := range allNodes {
		if n.GetType() == missionpb.NodeType_NODE_TYPE_CONDITION {
			for _, b := range append(append([]string{}, n.GetConditionConfig().GetTrueBranch()...), n.GetConditionConfig().GetFalseBranch()...) {
				deps.add(b, id)
			}
		}
	}

	// 4/5. Build WorkNodes for real nodes, rewriting deps through the resolver.
	nodes, err := buildWorkNodes(allNodes, deps, instanceSet(forEachInstances))
	if err != nil {
		return brain.MissionProjected{}, nil, err
	}

	return brain.MissionProjected{
		ID:          def.GetId(),
		Goal:        goal,
		Budget:      budgetFromConstraints(def.GetConstraints()),
		Nodes:       nodes,
		DeciderSlot: deciderSlotFrom(def.GetDeciderSlot()),
	}, origins, nil
}

// nodeDeps accumulates the raw dependency sets the projection builds before it
// rewrites them through the resolver. It is a set rather than a slice because
// the same edge arrives by three routes — a node's own `dependencies`, the
// definition's `edges`, and branch or fan-out gating added here.
type nodeDeps map[string]map[string]struct{}

// add records that `node` waits on `on`. A self-edge and an empty id are
// dropped: a node cannot wait on itself, and an empty id would create a
// dependency on a node that does not exist, which the resolver would then
// silently resolve to nothing.
func (d nodeDeps) add(node, on string) {
	if node == on || on == "" {
		return
	}
	if d[node] == nil {
		d[node] = map[string]struct{}{}
	}
	d[node][on] = struct{}{}
}

// flattenParallel returns one flat node set: every declared node, plus each
// parallel node's sub-nodes promoted to real nodes. The parallel node itself
// stays in the set but never becomes work — it collapses into DependsOn.
func flattenParallel(def *missionpb.MissionDefinition) (map[string]*missionpb.MissionNode, error) {
	allNodes := map[string]*missionpb.MissionNode{}
	for id, n := range def.GetNodes() {
		allNodes[id] = n
	}
	for id, n := range def.GetNodes() {
		if n.GetType() != missionpb.NodeType_NODE_TYPE_PARALLEL {
			continue
		}
		for _, sub := range n.GetParallelConfig().GetSubNodes() {
			if sub.GetId() == "" {
				return nil, fmt.Errorf("parallel node %q: sub-node missing id", id)
			}
			allNodes[sub.GetId()] = sub
		}
	}
	return allNodes, nil
}

// expandForEachNodes adds one bound instance per target to allNodes for every
// for_each node, and returns the instance ids keyed by for_each node id.
//
// The template itself never becomes a WorkNode — only its bound instances do,
// which is why the template's placeholders survive submit-time binding
// (targetbind.Bind skips them) and are bound here against each instance's own
// target.
func expandForEachNodes(
	def *missionpb.MissionDefinition,
	targets []forEachTarget,
	allNodes map[string]*missionpb.MissionNode,
) (map[string][]string, fanOutOrigins, error) {
	forEachInstances := map[string][]string{}
	origins := fanOutOrigins{}
	for id, n := range def.GetNodes() {
		if n.GetType() != missionpb.NodeType_NODE_TYPE_FOR_EACH {
			continue
		}
		tpl := n.GetForEachConfig().GetTemplate()
		if tpl == nil || tpl.GetId() == "" {
			return nil, nil, fmt.Errorf("for_each node %q: template missing or has no id", id)
		}
		if len(targets) == 0 {
			return nil, nil, fmt.Errorf(
				"for_each node %q: the run resolved no targets, so it would expand to nothing; "+
					"a mission that fans out needs at least one target", id)
		}
		insts, err := expandForEach(id, n, targets)
		if err != nil {
			return nil, nil, err
		}
		for k, inst := range insts {
			allNodes[inst.GetId()] = inst
			forEachInstances[id] = append(forEachInstances[id], inst.GetId())
			origins[inst.GetId()] = fanOutOrigin{
				ForEachNodeID: id,
				TemplateID:    tpl.GetId(),
				TargetID:      targets[k].ID,
			}
		}
	}
	return forEachInstances, origins, nil
}

// fanOutOrigin records where one fan-out instance came from.
//
// Every field is an output of expansion that the instance id cannot answer on its
// own: the id names the TEMPLATE and the target, not the for_each node that holds
// the template. The graph writer needs the for_each for SpawnedBy and the
// template for the definition metadata it still reads from the proto (gibson#528).
type fanOutOrigin struct {
	ForEachNodeID string
	TemplateID    string
	TargetID      string
}

// fanOutOrigins maps an instance's work-node id to where it came from. Empty for
// a mission with no for_each, which is every mission authored before fan-out.
type fanOutOrigins map[string]fanOutOrigin

// boundFanOut gives every instance the for_each node's own dependencies, then
// bounds how many instances run at once.
//
// The bound is built on DependsOn because nothing in the brain honours
// MaxConcurrency — ParallelNodeConfig has carried that field since it was
// written and `grep MaxConcurrency` over internal/engine/brain and
// internal/server/daemon finds no consumer (gibson#536).
//
// Chaining instance k behind instance k-limit bounds how many are runnable at
// once using the scheduler that already exists: with a limit of 4 and ten
// targets, instances 4..9 each wait on the one four places ahead, so at most
// four are ever ready. It costs ordering the author did not ask for, which is
// the honest trade for not launching fifty sandboxes at once.
func boundFanOut(def *missionpb.MissionDefinition, forEachInstances map[string][]string, deps nodeDeps) {
	for id, instIDs := range forEachInstances {
		for _, inst := range instIDs {
			for d := range deps[id] {
				deps.add(inst, d)
			}
		}
		limit := int(def.GetNodes()[id].GetForEachConfig().GetMaxConcurrency())
		if limit <= 0 || limit >= len(instIDs) {
			continue
		}
		for k := limit; k < len(instIDs); k++ {
			deps.add(instIDs[k], instIDs[k-limit])
		}
	}
}

// instanceSet flattens the per-for_each instance lists into one membership set,
// which is what the WorkNode builder needs: it asks whether one id is an
// instance, never which for_each produced it.
func instanceSet(forEachInstances map[string][]string) map[string]bool {
	out := map[string]bool{}
	for _, ids := range forEachInstances {
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

// buildWorkNodes turns the flat node set into the brain's WorkNodes, rewriting
// each dependency through the resolver so a dependency on a parallel, join or
// for_each node becomes a dependency on the real nodes it stands for.
func buildWorkNodes(
	allNodes map[string]*missionpb.MissionNode,
	deps nodeDeps,
	instances map[string]bool,
) ([]brain.WorkNode, error) {
	resolve := makeResolver(allNodes)
	var nodes []brain.WorkNode
	for id, n := range allNodes {
		switch n.GetType() {
		case missionpb.NodeType_NODE_TYPE_PARALLEL, missionpb.NodeType_NODE_TYPE_JOIN,
			missionpb.NodeType_NODE_TYPE_FOR_EACH:
			continue // collapsed into DependsOn; no entity
		}
		kind, target, input, err := nodeKindTargetInput(n)
		if err != nil {
			return nil, fmt.Errorf("node %q: %w", id, err)
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
			// A fan-out instance's terminal failure releases whatever waits on
			// it, so a join after a partially failed fan-out still reports the
			// targets that succeeded (gibson#527). Membership comes from the
			// expansion rather than from reading the id, because the id's shape
			// is an implementation detail and a node the author named with the
			// separator would otherwise be mistaken for an instance.
			DependentsRunOnFailure: instances[id],
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes, nil
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
		case missionpb.NodeType_NODE_TYPE_FOR_EACH:
			// Every instance, not the first: a join naming a for_each waits for
			// the whole fan-out (gibson#527). The instances are in `all` because
			// expansion put them there before the resolver was built.
			var out []string
			for _, cand := range instanceIDsOf(id, all) {
				out = append(out, resolve(cand, seen)...)
			}
			return out
		default:
			return []string{id}
		}
	}
	return func(id string) []string { return resolve(id, map[string]bool{}) }
}

func nodeKindTargetInput(n *missionpb.MissionNode) (kind, target, input string, err error) {
	// A node reaching projection still carrying a {{target.*}} placeholder was
	// never bound. Sending it on means dispatching a tool against the literal
	// text, and a tool handed a hostname that is not one reports a clean run
	// against a host that does not exist — the quietest way for a scan to find
	// nothing (gibson#495). Refuse it here, where the node becomes work.
	//
	// This is a backstop, not the binding. targetbind.Bind runs at run submit,
	// where the target is resolved and its ownership checked. If this ever
	// fires, a path built a run definition without binding it.
	if left := targetbind.UnboundTarget(n); len(left) > 0 {
		return "", "", "", fmt.Errorf("node %q was never bound to a target: %s",
			n.GetId(), strings.Join(left, ", "))
	}
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

// forEachTarget is one item of a for_each's source set: the target an instance
// runs against. It carries the resolved Target because binding needs its URL,
// host and name, and the UUID because that is the instance's identity.
type forEachTarget struct {
	ID     string
	Target *types.Target
}

// instanceIDPrefix separates a template's id from the target UUID that
// identifies one instance of it: `<templateID>#<targetUUID>`.
//
// The UUID and not an index. TargetSet() order is stable today, but an index
// survives a changed target set and then silently names a different host, which
// is the failure the whole fan-out design is built to avoid (gibson#524).
const instanceIDPrefix = "#"

// instanceID is the addressable identity of one for_each instance.
func instanceID(templateID, targetUUID string) string {
	return templateID + instanceIDPrefix + targetUUID
}

// instanceTargetID recovers the target an instance runs against from its work
// id, or "" when the id is not a for_each instance.
//
// Derived rather than carried. The alternative is threading the target through
// WorkNode, WorkItem, WorkDispatched and DispatchRequest, which is four places
// that can disagree with the id for one fact that the id already states. A
// finding attributed from a copy that drifted from the id would be attributed to
// the wrong host, which is precisely what this is for.
func instanceTargetID(workID string) string {
	i := strings.LastIndex(workID, instanceIDPrefix)
	if i < 0 || i == len(workID)-1 {
		return ""
	}
	return workID[i+len(instanceIDPrefix):]
}

// expandForEach clones the template once per target and binds each copy against
// that target. Order follows the target set, primary first, so the instance list
// is deterministic and the concurrency chain is stable between runs.
func expandForEach(nodeID string, n *missionpb.MissionNode, targets []forEachTarget) ([]*missionpb.MissionNode, error) {
	tpl := n.GetForEachConfig().GetTemplate()
	out := make([]*missionpb.MissionNode, 0, len(targets))
	for _, t := range targets {
		if t.Target == nil {
			return nil, fmt.Errorf("for_each node %q: target %q did not resolve", nodeID, t.ID)
		}
		bound, err := targetbind.BindNode(tpl, t.Target)
		if err != nil {
			return nil, fmt.Errorf("for_each node %q: %w", nodeID, err)
		}
		bound.Id = instanceID(tpl.GetId(), t.ID)
		// An instance's own dependencies are the for_each's, applied by the
		// caller. Whatever the template declared would name nodes that mean
		// something to the author, not to one instance.
		bound.Dependencies = nil
		out = append(out, bound)
	}
	return out, nil
}

// instanceIDsOf returns the instance ids expansion produced for a for_each,
// in target-set order, by matching the `<templateID>#` prefix in the node set.
//
// Derived from the node set rather than carried in a side map, so the resolver
// cannot disagree with what was actually projected.
func instanceIDsOf(nodeID string, all map[string]*missionpb.MissionNode) []string {
	n, ok := all[nodeID]
	if !ok {
		return nil
	}
	tplID := n.GetForEachConfig().GetTemplate().GetId()
	if tplID == "" {
		return nil
	}
	prefix := tplID + instanceIDPrefix
	var out []string
	for id := range all {
		if strings.HasPrefix(id, prefix) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
