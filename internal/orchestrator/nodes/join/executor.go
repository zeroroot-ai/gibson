// Package join implements the JOIN node executor.
//
// JOIN blocks until every node ID in JoinNodeConfig.wait_for has
// completed (success or final failure), then merges their results
// per the configured MergeStrategy. JOIN is separable from
// PARALLEL — a JOIN can merge results from non-parallel sibling
// branches.
//
// Spec: mission-verb-noun-registry Requirement 7.
package join

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// Execute is the NodeHandler for NODE_TYPE_JOIN.
func Execute(ctx context.Context, node *missionv1.MissionNode, params orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
	cfg := node.GetJoinConfig()
	if cfg == nil {
		return nil, fmt.Errorf("join executor: node %q has no join_config", node.GetId())
	}
	waitFor := cfg.GetWaitFor()
	if len(waitFor) == 0 {
		return nil, fmt.Errorf("join executor: node %q has empty wait_for", node.GetId())
	}

	// Collect upstream results. The orchestrator is responsible
	// for not invoking JOIN until every wait_for ID is in
	// PriorResults; we defensively assert it here and return
	// FailedPrecondition if anything is missing.
	sources := make(map[string]*orchestrator.ActionResult, len(waitFor))
	missing := []string{}
	for _, id := range waitFor {
		r, ok := params.PriorResults[id]
		if !ok || r == nil {
			missing = append(missing, id)
			continue
		}
		sources[id] = r
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("join executor: node %q wait_for has incomplete sources: %v", node.GetId(), missing)
	}

	merged, err := mergeResults(cfg, waitFor, sources)
	if err != nil {
		return nil, fmt.Errorf("join executor: node %q merge: %w", node.GetId(), err)
	}

	return &orchestrator.ActionResult{
		TargetNodeID: node.GetId(),
		Metadata: map[string]any{
			"join_strategy":     cfg.GetStrategy().String(),
			"join_wait_for":     waitFor,
			"join_merged_value": merged,
		},
	}, nil
}

// mergeResults applies the configured strategy to upstream
// results in source-declaration order (the order of wait_for).
func mergeResults(
	cfg *missionv1.JoinNodeConfig,
	waitFor []string,
	sources map[string]*orchestrator.ActionResult,
) (any, error) {
	switch cfg.GetStrategy() {
	case missionv1.MergeStrategy_MERGE_STRATEGY_UNSPECIFIED,
		missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT:
		// Order-preserving concat: list of (id, metadata) pairs.
		out := make([]map[string]any, 0, len(waitFor))
		for _, id := range waitFor {
			out = append(out, map[string]any{
				"node_id":  id,
				"metadata": sources[id].Metadata,
			})
		}
		return out, nil

	case missionv1.MergeStrategy_MERGE_STRATEGY_FIRST:
		return map[string]any{
			"node_id":  waitFor[0],
			"metadata": sources[waitFor[0]].Metadata,
		}, nil

	case missionv1.MergeStrategy_MERGE_STRATEGY_LAST:
		last := waitFor[len(waitFor)-1]
		return map[string]any{
			"node_id":  last,
			"metadata": sources[last].Metadata,
		}, nil

	case missionv1.MergeStrategy_MERGE_STRATEGY_REDUCE:
		// REDUCE folds source metadata maps into a flat map by
		// last-writer-wins. Useful when sources advertise
		// shared keys (e.g., findings_count, error_count).
		acc := map[string]any{}
		for _, id := range waitFor {
			for k, v := range sources[id].Metadata {
				acc[k] = v
			}
		}
		return acc, nil

	case missionv1.MergeStrategy_MERGE_STRATEGY_CUSTOM:
		// CUSTOM defers to a CEL aggregator. The CEL evaluator
		// shares its environment with the CONDITION executor; we
		// don't introduce a new dep here. For v1, when CUSTOM
		// is selected without an aggregator, fail at runtime
		// (submit-time validation also rejects this case, so
		// this is a defensive double-check).
		if cfg.GetAggregator() == "" {
			return nil, errors.New("MERGE_STRATEGY_CUSTOM requires non-empty aggregator")
		}
		// Until the shared CEL environment surfaces an
		// AggregatorEvaluator interface, return a structured
		// pending value so the executor's wiring is testable
		// end-to-end without coupling to the CEL evaluator's
		// implementation timing.
		return map[string]any{
			"strategy":   "MERGE_STRATEGY_CUSTOM",
			"aggregator": cfg.GetAggregator(),
			"sources":    waitFor,
			"pending":    true,
		}, nil

	default:
		return nil, fmt.Errorf("unknown MergeStrategy %v", cfg.GetStrategy())
	}
}

func init() {
	orchestrator.RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_JOIN, Execute)
}
