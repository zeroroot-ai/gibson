package parallel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// resetRegistryForTesting clears the global registry. We register
// stub handlers in tests so the executor can find a sub-node
// handler. Calling t.Cleanup with a re-init ensures isolation
// between tests within this package.
//
// Note: registry state is package-global in the orchestrator
// package, so these tests must run sequentially (the default for
// `go test` per-package).

type fakeRegistration struct {
	mu    sync.Mutex
	calls map[missionv1.NodeType]int
}

func parallelNode(id string, max int32, subs ...*missionv1.MissionNode) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:   id,
		Type: missionv1.NodeType_NODE_TYPE_PARALLEL,
		Config: &missionv1.MissionNode_ParallelConfig{
			ParallelConfig: &missionv1.ParallelNodeConfig{
				SubNodes:       subs,
				MaxConcurrency: max,
			},
		},
	}
}

func subNode(id string, t missionv1.NodeType) *missionv1.MissionNode {
	return &missionv1.MissionNode{Id: id, Type: t}
}

// fakeNodeType lets us register a stub handler without colliding
// with real ones. We pick one that's unlikely to be in use.
const stubType = missionv1.NodeType_NODE_TYPE_AGENT

func TestExecute_runs_all_subs(t *testing.T) {
	// Ensure a stub handler exists for the sub-node type. If a
	// real one is already registered (test cross-contamination)
	// we'll observe that and skip.
	if _, ok := orchestrator.ResolveNodeHandler(stubType); !ok {
		var counter int32
		orchestrator.RegisterNodeHandler(stubType, func(ctx context.Context, n *missionv1.MissionNode, p orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
			atomic.AddInt32(&counter, 1)
			return &orchestrator.ActionResult{Metadata: map[string]any{"id": n.GetId()}}, nil
		})
		// no t.Cleanup — the registry is build-time, can't unregister
	}

	node := parallelNode("p", 0,
		subNode("s1", stubType),
		subNode("s2", stubType),
		subNode("s3", stubType),
	)

	got, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Metadata["parallel_sub_nodes"] != 3 {
		t.Errorf("sub_nodes count = %v want 3", got.Metadata["parallel_sub_nodes"])
	}
	results := got.Metadata["parallel_results"].(map[string]*orchestrator.ActionResult)
	for _, id := range []string{"s1", "s2", "s3"} {
		if results[id] == nil {
			t.Errorf("sub %s missing from results", id)
		}
	}
}

func TestExecute_no_config(t *testing.T) {
	node := &missionv1.MissionNode{
		Id:   "p",
		Type: missionv1.NodeType_NODE_TYPE_PARALLEL,
	}
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestExecute_no_subs(t *testing.T) {
	node := parallelNode("p", 0)
	_, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err == nil {
		t.Fatal("expected error for empty sub_nodes")
	}
	if !strings.Contains(err.Error(), "no sub_nodes") {
		t.Errorf("error=%q want substring 'no sub_nodes'", err.Error())
	}
}

func TestExecute_handler_missing(t *testing.T) {
	// Use a node type unlikely to have a registered handler.
	const noHandler = missionv1.NodeType_NODE_TYPE_UNSPECIFIED
	node := parallelNode("p", 0, subNode("s", noHandler))
	got, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err != nil {
		t.Fatalf("Execute returned err=%v; expected per-sub failure to surface in metadata, not a top-level error from missing handler", err)
	}
	if got == nil {
		t.Fatal("got nil result")
	}
	failures := got.Metadata["parallel_failures"].([]string)
	if len(failures) != 1 {
		t.Errorf("failures=%d want=1: %v", len(failures), failures)
	}
}

func TestExecute_sibling_failure_isolated(t *testing.T) {
	// One sub fails, two succeed. All three must run to
	// completion; aggregate Error reports the failure.
	const failureType = missionv1.NodeType_NODE_TYPE_TOOL
	if _, ok := orchestrator.ResolveNodeHandler(failureType); !ok {
		orchestrator.RegisterNodeHandler(failureType, func(ctx context.Context, n *missionv1.MissionNode, p orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
			if n.GetId() == "fail" {
				return nil, errors.New("simulated tool failure")
			}
			return &orchestrator.ActionResult{Metadata: map[string]any{"id": n.GetId()}}, nil
		})
	}
	node := parallelNode("p", 0,
		subNode("ok-1", failureType),
		subNode("fail", failureType),
		subNode("ok-2", failureType),
	)
	got, err := Execute(context.Background(), node, orchestrator.HandlerParams{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Error == nil {
		t.Fatal("expected aggregated Error for sibling failure")
	}
	if !strings.Contains(got.Error.Error(), "fail") {
		t.Errorf("aggregated error doesn't mention failed sub: %v", got.Error)
	}
	results := got.Metadata["parallel_results"].(map[string]*orchestrator.ActionResult)
	if results["ok-1"] == nil || results["ok-2"] == nil {
		t.Errorf("siblings of failed sub missing from results: %v", results)
	}
}

func TestEffectiveConcurrency(t *testing.T) {
	cases := []struct {
		input int32
		want  int
	}{
		{0, DefaultGlobalMaxConcurrent},
		{-1, DefaultGlobalMaxConcurrent},
		{1, 1},
		{5, 5},
		{int32(DefaultGlobalMaxConcurrent), DefaultGlobalMaxConcurrent},
		{int32(DefaultGlobalMaxConcurrent + 100), DefaultGlobalMaxConcurrent},
	}
	for _, c := range cases {
		if got := effectiveConcurrency(c.input); got != c.want {
			t.Errorf("effectiveConcurrency(%d) = %d want %d", c.input, got, c.want)
		}
	}
}

// Compile-time use of fakeRegistration so the struct isn't
// flagged as unused.
var _ = fakeRegistration{}
