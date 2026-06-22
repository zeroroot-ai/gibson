package brain

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// condition.go is the mechanical branch System (CONTEXT.md: condition nodes
// survive the cutover as deterministic control flow, so a no-goal scripted
// mission branches without the Decider). A condition node is a WorkItem of kind
// "condition" carrying a ConditionSpec (JSON) in Input. When its deps are done,
// ConditionSystem evaluates the CEL expression over the World and records the
// outcome as a ConditionResolved event — so replay re-applies the decision
// deterministically rather than re-evaluating CEL.
//
// CEL environment (ported from internal/orchestrator/nodes/condition, equivalent
// semantics): `nodes` (map of completed WorkItem id → result string) and
// `mission` (map: id, goal). Expressions return a bool.

// celCostLimit caps per-evaluation CEL cost (mission-author safety; matches the
// legacy executor's conservative limit).
const celCostLimit uint64 = 50_000

// ConditionSpec is the condition node config carried in WorkItem.Input as JSON.
type ConditionSpec struct {
	Expression  string   `json:"expression"`
	TrueBranch  []string `json:"true_branch"`
	FalseBranch []string `json:"false_branch"`
}

// ConditionResolved records a condition's evaluated outcome: the condition node
// is marked done and the not-taken branch nodes are skipped.
type ConditionResolved struct {
	ID     string   // the condition WorkItem id
	Result bool     // the CEL boolean
	Skip   []string // not-taken branch node ids
}

func (ConditionResolved) Kind() string { return "condition.resolved" }

func applyConditionResolved(w *World, e ConditionResolved) {
	if ent, ok := findWork(w, e.ID); ok {
		wi := w.work.Get(ent)
		if wi.State == WorkPending || wi.State == WorkRunning {
			wi.State = WorkDone
			wi.Result = fmt.Sprintf("%t", e.Result)
		}
	}
	for _, id := range e.Skip {
		if ent, ok := findWork(w, id); ok {
			wi := w.work.Get(ent)
			if wi.State == WorkPending {
				wi.State = WorkSkipped
			}
		}
	}
}

// ConditionSystem resolves any pending condition node whose deps are all done.
func ConditionSystem(w *World) []Event {
	work := w.WorkSnapshot()
	state := workStateIndex(work)

	// `nodes` bag: completed work id → result string.
	nodeResults := map[string]any{}
	for _, wi := range work {
		if wi.State == WorkDone {
			nodeResults[wi.ID] = wi.Result
		}
	}

	var out []Event
	for _, wi := range work {
		if wi.Kind != "condition" || wi.State != WorkPending {
			continue
		}
		if !depsAllDone(wi.DependsOn, state) {
			continue
		}
		var spec ConditionSpec
		if err := json.Unmarshal([]byte(wi.Input), &spec); err != nil || spec.Expression == "" {
			// Malformed/empty condition is a mission-authoring error: fail the node.
			// Its branches depend on it, so they never become ready (dead) and the
			// mission settles as failed — deterministically.
			out = append(out, WorkCompleted{ID: wi.ID, Err: "malformed condition node"})
			continue
		}
		result := evalCondition(spec.Expression, nodeResults, missionBagFor(w, wi.MissionID))
		skip := spec.FalseBranch
		if !result {
			skip = spec.TrueBranch
		}
		out = append(out, ConditionResolved{ID: wi.ID, Result: result, Skip: append([]string(nil), skip...)})
	}
	return out
}

func missionBagFor(w *World, missionID string) map[string]any {
	bag := map[string]any{"id": missionID}
	for _, m := range w.MissionSnapshot() {
		if m.ID == missionID {
			bag["goal"] = m.Goal
			break
		}
	}
	return bag
}

// evalCondition compiles and evaluates a CEL boolean expression. A compile/eval
// error or non-boolean result yields false (the safe default — the true branch is
// skipped), keeping execution deterministic rather than stalling the mission.
func evalCondition(expr string, nodes, mission map[string]any) bool {
	env, err := cel.NewEnv(
		cel.Variable("nodes", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("mission", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return false
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return false
	}
	prog, err := env.Program(ast, cel.CostLimit(celCostLimit))
	if err != nil {
		return false
	}
	out, _, err := prog.ContextEval(context.Background(), map[string]any{"nodes": nodes, "mission": mission})
	if err != nil {
		return false
	}
	b, ok := out.(types.Bool)
	return ok && bool(b)
}
