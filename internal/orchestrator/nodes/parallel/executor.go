// Package parallel implements the PARALLEL node executor.
//
// PARALLEL fans out to its sub-nodes concurrently, capped by
// `max_concurrency`. Sibling failures are isolated — one failing
// sub-node does not cancel its siblings; each sub-node applies
// its own retry policy. The existing checkpoint markers in
// `internal/orchestrator/checkpoint_integration_parallel.go`
// fire on group completion and are not duplicated here.
//
// Spec: mission-verb-noun-registry Requirement 6.
package parallel

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"golang.org/x/sync/semaphore"
)

// DefaultGlobalMaxConcurrent caps PARALLEL fan-out when neither
// the node nor the orchestrator declare a stricter limit. Matches
// the orchestrator's default `maxConcurrent`.
const DefaultGlobalMaxConcurrent = 10

// Execute is the NodeHandler for NODE_TYPE_PARALLEL.
func Execute(ctx context.Context, node *missionv1.MissionNode, params orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
	cfg := node.GetParallelConfig()
	if cfg == nil {
		return nil, fmt.Errorf("parallel executor: node %q has no parallel_config", node.GetId())
	}
	subs := cfg.GetSubNodes()
	if len(subs) == 0 {
		return nil, fmt.Errorf("parallel executor: node %q has no sub_nodes", node.GetId())
	}

	cap := effectiveConcurrency(cfg.GetMaxConcurrency())
	sem := semaphore.NewWeighted(int64(cap))

	type subResult struct {
		nodeID string
		result *orchestrator.ActionResult
		err    error
	}
	results := make(chan subResult, len(subs))

	var wg sync.WaitGroup
	for _, sub := range subs {
		sub := sub
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := sem.Acquire(ctx, 1); err != nil {
				// Context cancellation propagates; record the
				// error but don't cancel siblings.
				results <- subResult{nodeID: sub.GetId(), err: err}
				return
			}
			defer sem.Release(1)

			handler, ok := orchestrator.ResolveNodeHandler(sub.GetType())
			if !ok {
				results <- subResult{
					nodeID: sub.GetId(),
					err:    fmt.Errorf("no handler registered for sub-node type %s", sub.GetType()),
				}
				return
			}

			// Each sub-node runs in isolation — propagate the
			// per-sub context (parent ctx) but do NOT cancel on
			// sibling failure.
			r, err := handler(ctx, sub, params)
			results <- subResult{nodeID: sub.GetId(), result: r, err: err}
		}()
	}
	wg.Wait()
	close(results)

	merged := make(map[string]*orchestrator.ActionResult, len(subs))
	failures := []string{}
	var errs []error
	for r := range results {
		if r.err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", r.nodeID, r.err))
			errs = append(errs, fmt.Errorf("sub-node %s: %w", r.nodeID, r.err))
		}
		if r.result != nil {
			merged[r.nodeID] = r.result
		}
	}

	out := &orchestrator.ActionResult{
		TargetNodeID: node.GetId(),
		Metadata: map[string]any{
			"parallel_sub_nodes":     countSubNodes(subs),
			"parallel_failures":      failures,
			"parallel_effective_cap": cap,
			"parallel_results":       merged,
		},
	}
	if len(errs) > 0 {
		// Aggregate sub-failures as a single non-fatal Error;
		// callers can still observe per-sub success in
		// parallel_results. Per Requirement 6 AC 3, sibling
		// failure does not cancel siblings — by the time we
		// reach here every sub has run to completion.
		out.Error = errors.Join(errs...)
	}
	return out, nil
}

// effectiveConcurrency clamps the per-node max_concurrency to
// the orchestrator's default. 0 from the proto means "unlimited
// up to orchestrator cap", which we map to DefaultGlobalMaxConcurrent.
func effectiveConcurrency(nodeCap int32) int {
	if nodeCap <= 0 {
		return DefaultGlobalMaxConcurrent
	}
	if int(nodeCap) > DefaultGlobalMaxConcurrent {
		return DefaultGlobalMaxConcurrent
	}
	return int(nodeCap)
}

func countSubNodes(subs []*missionv1.MissionNode) int { return len(subs) }

func init() {
	orchestrator.RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_PARALLEL, Execute)
}
