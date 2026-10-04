// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/cel-go/cel"
)

// anyType is the Go type a CEL result converts to: plain JSON-shaped values.
var anyType = reflect.TypeOf((*any)(nil)).Elem()

// join.go is the join System (gibson#543). A join node is a WorkItem of kind
// "join" carrying a JoinSpec (JSON) in Input. When every source it waits for is
// terminal, JoinSystem merges the sources' results by the declared strategy and
// records the merged value as the join's own result through WorkCompleted, so
// replay re-applies the merged value rather than re-evaluating a CEL program.
//
// Sources are keyed by the node id the author wrote. A for_each source is one
// entry per instance, in Timeline completion order, each `{target, result,
// error}`, so the merged value says which target produced what and which
// targets failed. A failed instance is visible, never absent: the fan-out
// decision (gibson#524) runs every instance and reports the ones that
// succeeded, and a join that silently dropped the failures would hide the
// shape of the run.

// JoinSpec is the join node config carried in WorkItem.Input as JSON.
type JoinSpec struct {
	// Strategy is the MergeStrategy name without its prefix: "", "CONCAT",
	// "REDUCE", "FIRST", "LAST" or "CUSTOM".
	Strategy string `json:"strategy"`
	// Aggregator is the CEL expression a CUSTOM strategy evaluates.
	Aggregator string `json:"aggregator,omitempty"`
	// Sources are the join's wait_for entries, in the order the author wrote.
	Sources []JoinSource `json:"sources"`
}

// JoinSource is one wait_for entry resolved to the work it stands for.
type JoinSource struct {
	// ID is the node id the author wrote; it is the key in `sources`.
	ID string `json:"id"`
	// Nodes are the node ids whose work this source reads: the node itself for
	// an ordinary source, every instance for a fan-out.
	Nodes []string `json:"nodes"`
	// FanOut marks a for_each source: its value is one entry per instance.
	FanOut bool `json:"fan_out,omitempty"`
	// Targets maps an instance node id to the target it ran against.
	Targets map[string]string `json:"targets,omitempty"`
}

// Merge strategy names, as JoinSpec.Strategy carries them.
const (
	JoinStrategyNone   = ""
	JoinStrategyConcat = "CONCAT"
	JoinStrategyReduce = "REDUCE"
	JoinStrategyFirst  = "FIRST"
	JoinStrategyLast   = "LAST"
	JoinStrategyCustom = "CUSTOM"
)

// joinEntry is one fan-out instance's contribution to a source.
type joinEntry struct {
	Target string `json:"target"`
	Result any    `json:"result"`
	Error  string `json:"error,omitempty"`
}

// JoinSystem resolves any pending join whose sources are all terminal.
func JoinSystem(w *World) []Event {
	work := w.WorkSnapshot()
	idx := workIndex(work)

	var out []Event
	for _, wi := range work {
		if wi.Kind != "join" || wi.State != WorkPending {
			continue
		}
		if !depsSatisfied(wi.DependsOn, idx) {
			continue
		}
		var spec JoinSpec
		if err := json.Unmarshal([]byte(wi.Input), &spec); err != nil {
			out = append(out, WorkCompleted{ID: wi.ID, Err: "malformed join node: " + err.Error()})
			continue
		}
		merged, err := mergeJoin(spec, wi.MissionID, idx)
		if err != nil {
			out = append(out, WorkCompleted{ID: wi.ID, Err: fmt.Sprintf("join %s: %v", nodeName(wi.ID), err)})
			continue
		}
		b, err := json.Marshal(merged)
		if err != nil {
			out = append(out, WorkCompleted{ID: wi.ID, Err: fmt.Sprintf("join %s: encode merged value: %v", nodeName(wi.ID), err)})
			continue
		}
		out = append(out, WorkCompleted{ID: wi.ID, Result: string(b)})
	}
	return out
}

// joinLeaf is one completed work item a source reads, with its Timeline order.
type joinLeaf struct {
	seq    uint64
	source string // the source id it belongs to
	entry  joinEntry
	fanOut bool
}

// mergeJoin builds the `sources` map and folds it by the strategy.
func mergeJoin(spec JoinSpec, missionID string, idx map[string]WorkSnapshot) (any, error) {
	sources := map[string]any{}
	var leaves []joinLeaf
	for _, src := range spec.Sources {
		if src.FanOut {
			entries := make([]joinLeaf, 0, len(src.Nodes))
			for _, n := range src.Nodes {
				wi, ok := idx[WorkID(missionID, n)]
				if !ok {
					return nil, fmt.Errorf("source %q names unknown work %q", src.ID, n)
				}
				entries = append(entries, joinLeaf{
					seq:    wi.CompletedSeq,
					source: src.ID,
					fanOut: true,
					entry:  joinEntry{Target: src.Targets[n], Result: decodeResult(wi), Error: wi.Err},
				})
			}
			// Timeline order, so FIRST/LAST and CONCAT read as the run happened.
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].seq < entries[j].seq })
			vals := make([]any, 0, len(entries))
			for _, e := range entries {
				vals = append(vals, e.entry)
			}
			sources[src.ID] = vals
			leaves = append(leaves, entries...)
			continue
		}
		if len(src.Nodes) != 1 {
			return nil, fmt.Errorf("source %q resolves to %d nodes, want one", src.ID, len(src.Nodes))
		}
		wi, ok := idx[WorkID(missionID, src.Nodes[0])]
		if !ok {
			return nil, fmt.Errorf("source %q names unknown work %q", src.ID, src.Nodes[0])
		}
		val := decodeResult(wi)
		sources[src.ID] = val
		leaves = append(leaves, joinLeaf{seq: wi.CompletedSeq, source: src.ID, entry: joinEntry{Result: val, Error: wi.Err}})
	}

	switch spec.Strategy {
	case JoinStrategyNone:
		// No rule declared: the join is the ordering it always was, and its
		// result is the sources themselves, so nothing a source said is lost.
		return sources, nil
	case JoinStrategyConcat:
		// Source order as written; a fan-out contributes its entries in
		// Timeline order.
		out := make([]any, 0, len(leaves))
		for _, src := range spec.Sources {
			if src.FanOut {
				out = append(out, sources[src.ID].([]any)...)
				continue
			}
			out = append(out, sources[src.ID])
		}
		return out, nil
	case JoinStrategyReduce:
		// A deep merge of every object value, in source order then Timeline
		// order; a later key overwrites an earlier one, nested objects merge.
		acc := map[string]any{}
		for _, src := range spec.Sources {
			if src.FanOut {
				for _, e := range sources[src.ID].([]any) {
					deepMerge(acc, e.(joinEntry).Result)
				}
				continue
			}
			deepMerge(acc, sources[src.ID])
		}
		return acc, nil
	case JoinStrategyFirst, JoinStrategyLast:
		if len(leaves) == 0 {
			return nil, fmt.Errorf("strategy %s over no sources", spec.Strategy)
		}
		sort.SliceStable(leaves, func(i, j int) bool { return leaves[i].seq < leaves[j].seq })
		pick := leaves[0]
		if spec.Strategy == JoinStrategyLast {
			pick = leaves[len(leaves)-1]
		}
		if pick.fanOut {
			return pick.entry, nil
		}
		return pick.entry.Result, nil
	case JoinStrategyCustom:
		return evalAggregator(spec.Aggregator, sources)
	default:
		return nil, fmt.Errorf("unknown merge strategy %q", spec.Strategy)
	}
}

// decodeResult reads a work item's result as JSON when it is JSON, else as the
// raw string. A failed item has no result.
func decodeResult(wi WorkSnapshot) any {
	if wi.State != WorkDone {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(wi.Result), &v); err == nil {
		return v
	}
	return wi.Result
}

// deepMerge folds src into acc when src is an object; a non-object value has
// nothing to merge by key and is kept under "_" so it is not dropped.
func deepMerge(acc map[string]any, src any) {
	obj, ok := src.(map[string]any)
	if !ok {
		if src != nil {
			acc["_"] = append(toSlice(acc["_"]), src)
		}
		return
	}
	for k, v := range obj {
		if existing, ok := acc[k].(map[string]any); ok {
			if inner, ok := v.(map[string]any); ok {
				deepMerge(existing, inner)
				continue
			}
		}
		acc[k] = v
	}
}

func toSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// evalAggregator compiles and evaluates the CEL aggregator with `sources`
// bound. A compile or evaluation error fails the join and names the
// expression, so an author learns their rule did not run rather than reading a
// silently merged value.
func evalAggregator(expr string, sources map[string]any) (any, error) {
	if expr == "" {
		return nil, fmt.Errorf("strategy CUSTOM declares no aggregator")
	}
	env, err := cel.NewEnv(cel.Variable("sources", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		return nil, fmt.Errorf("aggregator %q: environment: %w", expr, err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("aggregator %q: %w", expr, issues.Err())
	}
	prog, err := env.Program(ast, cel.CostLimit(celCostLimit))
	if err != nil {
		return nil, fmt.Errorf("aggregator %q: program: %w", expr, err)
	}
	out, _, err := prog.ContextEval(context.Background(), map[string]any{"sources": toCEL(sources)})
	if err != nil {
		return nil, fmt.Errorf("aggregator %q: %w", expr, err)
	}
	native, err := out.ConvertToNative(anyType)
	if err != nil {
		return nil, fmt.Errorf("aggregator %q: result %v is not representable: %w", expr, out, err)
	}
	return native, nil
}

// toCEL turns the sources map into plain JSON-shaped values: CEL binds Go maps
// and slices of `any`, not the joinEntry struct.
func toCEL(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = toCEL(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = toCEL(val)
		}
		return out
	case joinEntry:
		m := map[string]any{"target": x.Target, "result": toCEL(x.Result)}
		if x.Error != "" {
			m["error"] = x.Error
		}
		return m
	default:
		return v
	}
}
