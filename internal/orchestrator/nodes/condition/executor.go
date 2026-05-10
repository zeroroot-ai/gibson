// Package condition implements the CONDITION node executor.
//
// CONDITION evaluates a CEL expression against the accumulated
// mission state and dispatches downstream execution to the
// `true_branch` or `false_branch` node-ID list based on the
// boolean result.
//
// Expression environment exposes:
//
//   nodes        map[string]dyn — prior node results keyed by ID
//   mission      map[string]dyn — mission-level metadata
//   constraints  MissionConstraints — the proto type
//
// Currently only `LANGUAGE_CEL` (and `LANGUAGE_UNSPECIFIED`
// which defaults to CEL) is supported. Other language values
// fail with codes.Unimplemented.
//
// Spec: mission-verb-noun-registry Requirement 5.
package condition

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// CostLimit is the per-evaluation CEL cost cap. Conservative
// value chosen for mission-author safety; can be raised after
// benchmarks settle if real expressions hit it.
const CostLimit uint64 = 50_000

// programCache caches compiled cel.Program by (missionID, nodeID,
// expression-hash). The orchestrator currently calls Execute
// once per node activation; the cache is here for future
// reuse cases (e.g., re-evaluating on retry).
type programCache struct {
	mu    sync.RWMutex
	progs map[string]cel.Program
}

func (c *programCache) get(key string) (cel.Program, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.progs[key]
	return p, ok
}

func (c *programCache) set(key string, p cel.Program) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.progs == nil {
		c.progs = make(map[string]cel.Program)
	}
	c.progs[key] = p
}

var globalCache = &programCache{}

// Env returns a fresh CEL environment with the documented
// variable surface. Exported so the JOIN executor's CUSTOM
// aggregator can share the same env.
func Env() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("nodes", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("mission", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("constraints", cel.DynType),
	)
}

// Execute is the NodeHandler for NODE_TYPE_CONDITION.
func Execute(ctx context.Context, node *missionv1.MissionNode, params orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
	cfg := node.GetConditionConfig()
	if cfg == nil {
		return nil, fmt.Errorf("condition executor: node %q has no condition_config", node.GetId())
	}
	expr := cfg.GetExpression()
	if expr == "" {
		return nil, fmt.Errorf("condition executor: node %q has empty expression", node.GetId())
	}
	switch cfg.GetLanguage() {
	case missionv1.Language_LANGUAGE_UNSPECIFIED, missionv1.Language_LANGUAGE_CEL:
		// supported
	default:
		return nil, fmt.Errorf("condition executor: unsupported language %s on node %q", cfg.GetLanguage(), node.GetId())
	}

	cacheKey := params.MissionID + "\x00" + node.GetId() + "\x00" + expr
	prog, ok := globalCache.get(cacheKey)
	if !ok {
		env, err := Env()
		if err != nil {
			return nil, fmt.Errorf("condition executor: build env: %w", err)
		}
		ast, issues := env.Compile(expr)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("condition executor: compile expression %q: %w", expr, issues.Err())
		}
		// Cost limit; default macros + basic stdlib only.
		p, err := env.Program(ast, cel.CostLimit(CostLimit))
		if err != nil {
			return nil, fmt.Errorf("condition executor: build program: %w", err)
		}
		prog = p
		globalCache.set(cacheKey, prog)
	}

	in := buildEvaluationInput(params)
	out, _, err := prog.ContextEval(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("condition executor: evaluate %q: %w", expr, err)
	}
	boolVal, ok := out.(types.Bool)
	if !ok {
		return nil, fmt.Errorf("condition executor: expression %q returned non-boolean type %T", expr, out)
	}

	taken := bool(boolVal)
	branchTaken := cfg.GetTrueBranch()
	branchSkipped := cfg.GetFalseBranch()
	if !taken {
		branchTaken, branchSkipped = branchSkipped, branchTaken
	}

	return &orchestrator.ActionResult{
		TargetNodeID: node.GetId(),
		Metadata: map[string]any{
			"condition_expression": expr,
			"condition_result":     taken,
			"branch_ready":         branchTaken,
			"branch_skipped":       branchSkipped,
		},
	}, nil
}

// buildEvaluationInput constructs the CEL input bag from the
// orchestrator's HandlerParams.
func buildEvaluationInput(params orchestrator.HandlerParams) map[string]any {
	nodes := make(map[string]any, len(params.PriorResults))
	for id, r := range params.PriorResults {
		if r == nil {
			continue
		}
		nodes[id] = r.Metadata
	}
	missionMeta := map[string]any{
		"id": params.MissionID,
	}
	if params.Definition != nil {
		missionMeta["name"] = params.Definition.GetName()
		missionMeta["version"] = params.Definition.GetVersion()
	}
	return map[string]any{
		"nodes":       nodes,
		"mission":     missionMeta,
		"constraints": map[string]any{}, // Filled in by the orchestrator when MissionConstraints surfaces in HandlerParams; placeholder keeps the variable resolvable.
	}
}

func init() {
	orchestrator.RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_CONDITION, Execute)
}
