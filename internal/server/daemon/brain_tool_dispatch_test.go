// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"
	"google.golang.org/protobuf/proto"
)

// toolHarness is an AgentHarness that only answers CallToolProto. Embedding the
// interface keeps the fake to the one method under test — every other call
// panics on the nil interface, which is what a test wants: an unexpected harness
// call is a bug, not a silent pass.
type toolHarness struct {
	gibsonharness.AgentHarness

	gotName  string
	gotInput string

	output  string
	toolErr string
	err     error

	// forTargetID records what dispatchTool asked the harness to re-scope to, so
	// a test can assert a for_each instance is dispatched against its own target.
	forTargetID string

	// gotNetwork is the node network on the context of the call.
	gotNetwork *agent.NodeNetwork
}

// ForTarget records the request and returns the same stub, so the assertions
// below see one object. The real implementation returns a view; what matters
// here is WHICH target the dispatcher asked for.
func (h *toolHarness) ForTarget(targetID string) gibsonharness.AgentHarness {
	h.forTargetID = targetID
	return h
}

func (h *toolHarness) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	h.gotName = name
	h.gotNetwork = gibsonharness.NodeNetworkFromContext(ctx)
	if req, ok := request.(*toolpb.ExecuteRequest); ok {
		h.gotInput = req.GetInputJson()
	}
	if h.err != nil {
		return h.err
	}
	resp, ok := response.(*toolpb.ExecuteResponse)
	if !ok {
		return errors.New("unexpected response type")
	}
	resp.OutputJson = h.output
	if h.toolErr != "" {
		resp.Error = &commonpb.Error{Message: h.toolErr}
	}
	return nil
}

func TestDispatchTool_PassesNodeInputThroughAndReturnsOutput(t *testing.T) {
	h := &toolHarness{output: `{"status":200}`}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}

	out, err := b.dispatchTool(bind, brain.DispatchRequest{
		WorkID: "w1",
		Kind:   "tool",
		Target: "zerocool-http",
		Input:  `{"url":"https://google.com"}`,
	})
	if err != nil {
		t.Fatalf("dispatchTool: %v", err)
	}
	if h.gotName != "zerocool-http" {
		t.Errorf("tool name = %q, want zerocool-http", h.gotName)
	}
	// The node's parameters must reach the tool verbatim — reshaping them here
	// would silently change what the mission asked for.
	if h.gotInput != `{"url":"https://google.com"}` {
		t.Errorf("input_json = %q, want the node input unchanged", h.gotInput)
	}
	if out != `{"status":200}` {
		t.Errorf("result = %q, want the tool output", out)
	}
}

func TestDispatchTool_EmptyInputIsNotAnError(t *testing.T) {
	// A tool that takes no parameters is ordinary; failing the node here would
	// make such a mission impossible to write.
	h := &toolHarness{output: `{"ok":true}`}
	b := newBrainExecutor(nil, slog.Default())
	if _, err := b.dispatchTool(&missionBinding{ctx: context.Background(), harness: h},
		brain.DispatchRequest{Kind: "tool", Target: "ping"}); err != nil {
		t.Fatalf("dispatchTool with no input: %v", err)
	}
	if h.gotInput != "" {
		t.Errorf("input_json = %q, want empty", h.gotInput)
	}
}

func TestDispatchTool_SurfacesToolReportedError(t *testing.T) {
	// A tool answering with ExecuteResponse.error is a failed node, not a
	// successful one with a strange result — the mission must see the reason.
	h := &toolHarness{toolErr: "http_probe requires a `url` parameter"}
	b := newBrainExecutor(nil, slog.Default())
	_, err := b.dispatchTool(&missionBinding{ctx: context.Background(), harness: h},
		brain.DispatchRequest{Kind: "tool", Target: "zerocool-http"})
	if err == nil {
		t.Fatal("expected an error when the tool reports one")
	}
	if !strings.Contains(err.Error(), "requires a `url`") {
		t.Errorf("error = %v, want the tool's own message", err)
	}
}

func TestDispatchTool_SurfacesTransportError(t *testing.T) {
	h := &toolHarness{err: errors.New("no component registered")}
	b := newBrainExecutor(nil, slog.Default())
	_, err := b.dispatchTool(&missionBinding{ctx: context.Background(), harness: h},
		brain.DispatchRequest{Kind: "tool", Target: "missing"})
	if err == nil || !strings.Contains(err.Error(), "no component registered") {
		t.Fatalf("error = %v, want the harness error surfaced", err)
	}
}

func TestDispatchTool_RejectsNamelessTool(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())
	if _, err := b.dispatchTool(&missionBinding{ctx: context.Background(), harness: &toolHarness{}},
		brain.DispatchRequest{Kind: "tool"}); err == nil {
		t.Fatal("expected an error for a tool node with no tool name")
	}
}

// dispatchOutcome runs a Dispatch through a real engine and returns the
// WorkCompleted the executor reported. Dispatch is asynchronous, so the engine
// is ticked until the event lands.
func dispatchOutcome(t *testing.T, h gibsonharness.AgentHarness, req brain.DispatchRequest) brain.WorkCompleted {
	t.Helper()
	return dispatchOutcomeWithData(t, h, req, nil)
}

// dispatchOutcomeWithData is dispatchOutcome for a mission with task data.
func dispatchOutcomeWithData(t *testing.T, h gibsonharness.AgentHarness, req brain.DispatchRequest, data map[string]any) brain.WorkCompleted {
	t.Helper()
	eng := brain.NewEngine("tenant-a", braintest.NewMemTimelineStore())
	got := make(chan brain.WorkCompleted, 1)
	eng.Subscribe(func(ev brain.Event) {
		if wc, ok := ev.(brain.WorkCompleted); ok {
			select {
			case got <- wc:
			default:
			}
		}
	})

	b := newBrainExecutor(nil, slog.Default())
	req.MissionID = "m1"
	b.register(req.MissionID, &missionBinding{ctx: context.Background(), eng: eng, harness: h, taskData: data})
	b.Dispatch(req)

	deadline := time.After(5 * time.Second)
	for {
		eng.Tick()
		select {
		case wc := <-got:
			return wc
		case <-deadline:
			t.Fatal("no WorkCompleted within the deadline")
		default:
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDispatch_ToolNodeCompletesThroughTheHarness(t *testing.T) {
	// The regression this guards: tool nodes were refused outright, so a mission
	// whose only node was a tool started and then never progressed or failed
	// (gibson#1196).
	h := &toolHarness{output: `{"status":200}`}
	wc := dispatchOutcome(t, h, brain.DispatchRequest{WorkID: "w1", Kind: "tool", Target: "zerocool-http", Input: `{"url":"https://google.com"}`})
	if wc.Err != "" {
		t.Fatalf("WorkCompleted.Err = %q, want success", wc.Err)
	}
	if wc.Result != `{"status":200}` {
		t.Errorf("WorkCompleted.Result = %q, want the tool output", wc.Result)
	}
}

func TestDispatch_ToolFailureFailsTheWorkItem(t *testing.T) {
	h := &toolHarness{err: errors.New("boom")}
	wc := dispatchOutcome(t, h, brain.DispatchRequest{WorkID: "w1", Kind: "tool", Target: "t"})
	if wc.Err == "" {
		t.Fatal("expected the work item to fail, not to complete silently")
	}
}

func TestDispatch_UnsupportedKindFailsFastWithAReason(t *testing.T) {
	// Plugin dispatch is still unimplemented; it must fail the work item rather
	// than leave the mission hanging.
	wc := dispatchOutcome(t, &toolHarness{}, brain.DispatchRequest{WorkID: "w1", Kind: "plugin", Target: "p"})
	if !strings.Contains(wc.Err, "plugin") {
		t.Errorf("WorkCompleted.Err = %q, want it to name the unsupported kind", wc.Err)
	}
}

// A for_each instance is dispatched against ITS OWN target, so the findings it
// produces carry that target's scope rather than the mission's primary.
//
// This is the assertion the attribution slice rests on: every scope reader in
// the callback surface resolves from h.Target().ID, so if the dispatcher hands
// over the mission's harness unchanged, instance B's findings land on instance
// A's host and several machines merge onto one coordinate (gibson#526).
func TestDispatchTool_ForEachInstanceIsScopedToItsOwnTarget(t *testing.T) {
	const target = "22222222-2222-2222-2222-222222222222"
	h := &toolHarness{output: `{"status":200}`}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}

	if _, err := b.dispatchTool(bind, brain.DispatchRequest{
		WorkID: "scan#" + target,
		Kind:   "tool",
		Target: "nmap",
		Input:  `{"target":"10.0.0.2"}`,
	}); err != nil {
		t.Fatalf("dispatchTool: %v", err)
	}

	if h.forTargetID != target {
		t.Errorf("dispatched against target %q, want %q — a fan-out instance must "+
			"be scoped to the target its work id names", h.forTargetID, target)
	}
}

// An ordinary node does not re-scope, and must not call ForTarget at all: a
// harness that embeds the AgentHarness interface has a nil embedded value, so an
// unconditional call would panic on every dispatch in the system.
func TestDispatchTool_OrdinaryNodeDoesNotRescope(t *testing.T) {
	h := &toolHarness{output: `{"status":200}`}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}

	if _, err := b.dispatchTool(bind, brain.DispatchRequest{
		WorkID: "scan",
		Kind:   "tool",
		Target: "nmap",
		Input:  `{}`,
	}); err != nil {
		t.Fatalf("dispatchTool: %v", err)
	}

	if h.forTargetID != "" {
		t.Errorf("ForTarget was called with %q for a non-instance node; it must not "+
			"be called at all", h.forTargetID)
	}
}

// A tool node gets the network of its node, as an agent node does. Before this,
// dispatchTool dropped req.Network, so the tool sandbox took the default mode of
// its class instead of the targets bound to the node.
func TestDispatchTool_PassesTheNodeNetworkToTheTool(t *testing.T) {
	h := &toolHarness{output: `{"status":200}`}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}
	network := &agent.NodeNetwork{Targets: []string{"10.60.0.66:6443"}}

	if _, err := b.dispatchTool(bind, brain.DispatchRequest{
		WorkID:  "scan",
		Kind:    "tool",
		Target:  "nmap",
		Input:   `{}`,
		Network: network,
	}); err != nil {
		t.Fatalf("dispatchTool: %v", err)
	}

	if h.gotNetwork != network {
		t.Errorf("the tool call carried network %+v, want %+v", h.gotNetwork, network)
	}
}

type fakeMissionConnector struct {
	tenant, mission, run, work, connector, tool string
	args                                        map[string]any
	result                                      any
	err                                         error
	// errs are the errors of the first calls, in order. The call after the last
	// one returns result and err.
	errs []error
	// mu guards every field above, because the node calls on its own goroutine
	// while the test reads the count.
	mu    sync.Mutex
	calls int
}

// callCount returns the number of calls, safe against a running node.
func (f *fakeMissionConnector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeMissionConnector) CallConnectorForMission(
	_ context.Context, tenant, missionID, runID, workID, connector, tool string, args map[string]any,
) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenant, f.mission, f.run, f.work, f.connector, f.tool, f.args = tenant, missionID, runID, workID, connector, tool, args
	f.calls++
	if f.calls <= len(f.errs) {
		return nil, f.errs[f.calls-1]
	}
	return f.result, f.err
}

// A TOOL node that names mcp:<connector>:<tool> calls the connector with the
// tenant and the run of its binding, and its input is the argument object. The
// harness tool path is not used (gibson#1469).
func TestDispatchTool_AConnectorToolTakesTheGovernedPath(t *testing.T) {
	h := &toolHarness{output: `{"never":"used"}`}
	conn := &fakeMissionConnector{result: map[string]any{"alerts": []any{}}}
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = conn
	bind := &missionBinding{ctx: context.Background(), harness: h, tenant: "acme", runID: "run-9"}

	out, err := b.dispatchTool(bind, brain.DispatchRequest{
		WorkID: "w1", MissionID: "m1", Kind: "tool", Target: "mcp:github-fixloop:read_file", Input: `{"path":"go.mod"}`,
	})
	if err != nil {
		t.Fatalf("dispatchTool: %v", err)
	}
	if out != `{"alerts":[]}` {
		t.Errorf("out = %q", out)
	}
	if conn.work != "w1" {
		t.Errorf("the call names work %q, want the node w1", conn.work)
	}
	if conn.tenant != "acme" || conn.run != "run-9" || conn.mission != "m1" || conn.connector != "github-fixloop" || conn.tool != "read_file" {
		t.Errorf("call = %+v", conn)
	}
	if conn.args["path"] != "go.mod" {
		t.Errorf("args = %v", conn.args)
	}
	if h.gotName != "" {
		t.Errorf("the harness tool path ran for %q", h.gotName)
	}

	// A refusal of the governed path ends the node, and a bad input does too.
	conn.err = errors.New("not allowed")
	if _, err := b.dispatchTool(bind, brain.DispatchRequest{Target: "mcp:github-fixloop:read_file"}); err == nil {
		t.Error("a refused call must fail the node")
	}
	if _, err := b.dispatchTool(bind, brain.DispatchRequest{Target: "mcp:github-fixloop:read_file", Input: `[1]`}); err == nil {
		t.Error("an input that is not an object must fail the node")
	}
	b.connectors = nil
	if _, err := b.dispatchTool(bind, brain.DispatchRequest{Target: "mcp:github-fixloop:read_file"}); err == nil {
		t.Error("a daemon with no connector caller must fail the node")
	}
}

// A call that returns nothing with no error fails the node. It does not succeed
// with "null".
func TestDispatchTool_ANilConnectorResultFailsTheNode(t *testing.T) {
	conn := &fakeMissionConnector{}
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = conn
	bind := &missionBinding{ctx: context.Background(), tenant: "acme", runID: "run-9"}
	if out, err := b.dispatchTool(bind, brain.DispatchRequest{Target: "mcp:github-fixloop:read_file"}); err == nil {
		t.Fatalf("a nil result must fail the node, got %q", out)
	}
}

// requestApproval puts an approval request of a tool call in the World, as the
// approval queue does when a marked tool is called.
func requestApproval(t *testing.T, eng *brain.Engine, id string) {
	t.Helper()
	if err := eng.SubmitAndWait(context.Background(), brain.DestructiveActionRequested{
		HypothesisID: id, Tenant: "acme", MissionID: "m1", ActionKind: brain.ActionKindToolCall,
		Connector: "crowdstrike-response", Tool: "isolate_x", ArgsHash: "h",
	}); err != nil {
		t.Fatal(err)
	}
}

func decideApproval(t *testing.T, eng *brain.Engine, id string, approved bool) {
	t.Helper()
	if err := eng.SubmitAndWait(context.Background(), brain.DestructiveActionDecided{HypothesisID: id, Approved: approved, UserID: "u1"}); err != nil {
		t.Fatal(err)
	}
}

// A tool with an approval mark waits for a person. The node records the request
// id on its work item and moves to input_required once. It calls Handler.Call
// again only after the request is decided, so a decision costs one intent record
// and one result record and a poll costs none. A denial fails the node.
func TestDispatchTool_AMarkedToolWaitsForTheDecisionAndCallsOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	requestApproval(t, eng, "req-1")
	conn := &fakeMissionConnector{errs: []error{&metatool.PendingApproval{ID: "req-1"}}, result: map[string]any{"ok": true}}
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = conn
	b.approvalPoll = time.Millisecond
	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-9", eng: eng}

	type outcome struct {
		out string
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		out, err := b.dispatchTool(bind, brain.DispatchRequest{WorkID: "w1", MissionID: "m1", Target: "mcp:crowdstrike-response:isolate_x"})
		done <- outcome{out, err}
	}()
	// While the request is open, the node does not call again, however long it waits.
	time.Sleep(60 * time.Millisecond)
	if conn.callCount() != 1 {
		t.Fatalf("the node called %d times while the request was open, want 1", conn.callCount())
	}
	select {
	case o := <-done:
		t.Fatalf("the node ended before the decision: %+v", o)
	default:
	}
	decideApproval(t, eng, "req-1", true)
	select {
	case o := <-done:
		if o.err != nil || o.out != `{"ok":true}` {
			t.Fatalf("out = %q, err = %v", o.out, o.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the node did not resume after the decision")
	}
	if conn.callCount() != 2 {
		t.Errorf("calls = %d, want the first call and one call after the decision", conn.callCount())
	}
}

// A denial reaches the node through the second call, which the gate answers with
// the denial. The node fails with it.
func TestDispatchTool_ADeniedApprovalFailsTheNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	requestApproval(t, eng, "req-2")
	decideApproval(t, eng, "req-2", false)
	conn := &fakeMissionConnector{errs: []error{
		&metatool.PendingApproval{ID: "req-2"}, fmt.Errorf("%w: request req-2", metatool.ErrApprovalDenied),
	}}
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = conn
	b.approvalPoll = time.Millisecond
	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-9", eng: eng}
	_, err := b.dispatchTool(bind, brain.DispatchRequest{WorkID: "w2", MissionID: "m1", Target: "mcp:crowdstrike-response:isolate_x"})
	if !errors.Is(err, metatool.ErrApprovalDenied) {
		t.Fatalf("a denial must fail the node, got %v", err)
	}
}

// The wait ends with the bound of the node, with the end of the mission, and with
// a request that is gone.
func TestDispatchTool_TheApprovalWaitIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	requestApproval(t, eng, "req-3")
	pending := &fakeMissionConnector{err: &metatool.PendingApproval{ID: "req-3"}}
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = pending
	b.approvalPoll = time.Millisecond
	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-9", eng: eng}

	if _, err := b.dispatchTool(bind, brain.DispatchRequest{WorkID: "w3", MissionID: "m1", Timeout: 30 * time.Millisecond, Target: "mcp:crowdstrike-response:isolate_x"}); err == nil ||
		!strings.Contains(err.Error(), "bound of the node") {
		t.Errorf("the bound of the node must end the wait, got %v", err)
	}
	// The request shows as withdrawn, and a verdict after that changes nothing.
	var withdrawn, decided bool
	var reason string
	eng.ReadWorld(func(w *brain.World) {
		for _, a := range w.DestructiveActionSnapshot() {
			if a.HypothesisID == "req-3" {
				withdrawn, decided, reason = a.Withdrawn, a.Decided, a.WithdrawnReason
			}
		}
	})
	if !withdrawn || !decided || !strings.Contains(reason, "bound of the node") {
		t.Errorf("the request after the timeout: withdrawn=%v decided=%v reason=%q", withdrawn, decided, reason)
	}
	if err := eng.DestructiveAuthorizationQueue().Decide("req-3", "u1", true); err == nil {
		t.Error("a person approved a request whose node is gone")
	}
	eng.Submit(brain.DestructiveActionDecided{HypothesisID: "req-3", Approved: true, UserID: "u1"})
	time.Sleep(50 * time.Millisecond)
	eng.ReadWorld(func(w *brain.World) {
		for _, a := range w.DestructiveActionSnapshot() {
			if a.HypothesisID == "req-3" && (a.Approved || a.UserID != "") {
				t.Errorf("an approval after the withdrawal changed the request: %+v", a)
			}
		}
	})
	gone := &fakeMissionConnector{err: &metatool.PendingApproval{ID: "req-missing"}}
	b.connectors = gone
	if _, err := b.dispatchTool(bind, brain.DispatchRequest{WorkID: "w4", MissionID: "m1", Target: "mcp:crowdstrike-response:isolate_x"}); err == nil ||
		!strings.Contains(err.Error(), "the request is gone") {
		t.Errorf("a request that is gone must fail the node, got %v", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	b.connectors = pending
	if _, err := b.dispatchTool(&missionBinding{ctx: canceled, tenant: "acme", runID: "run-9", eng: eng},
		brain.DispatchRequest{WorkID: "w5", MissionID: "m1", Target: "mcp:crowdstrike-response:isolate_x"}); err == nil {
		t.Error("a canceled mission must end the wait")
	}
}

// A node that declares no timeout waits at most maxApprovalWait. Then it fails
// and its request is withdrawn.
func TestDispatchTool_ANodeWithNoTimeoutWaitsAtMostTheCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	requestApproval(t, eng, "req-7")
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = &fakeMissionConnector{err: &metatool.PendingApproval{ID: "req-7"}}
	b.approvalPoll = time.Millisecond
	b.approvalMaxWait = 30 * time.Millisecond
	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-9", eng: eng}
	if maxApprovalWait != 24*time.Hour {
		t.Fatalf("maxApprovalWait = %v, want 24h", maxApprovalWait)
	}
	_, err := b.dispatchTool(bind, brain.DispatchRequest{WorkID: "w7", MissionID: "m1", Target: "mcp:crowdstrike-response:isolate_x"})
	if err == nil || !strings.Contains(err.Error(), "bound of the node") {
		t.Fatalf("the cap must end the wait, got %v", err)
	}
	var withdrawn bool
	eng.ReadWorld(func(w *brain.World) {
		for _, a := range w.DestructiveActionSnapshot() {
			withdrawn = withdrawn || (a.HypothesisID == "req-7" && a.Withdrawn)
		}
	})
	if !withdrawn {
		t.Error("the request of a node that stopped waiting is not withdrawn")
	}
}

// A binding with no World cannot wait for an approval, and a node with no timeout
// uses the cap that ends with the mission.
func TestWaitForApproval_NoWorldAndTheDefaultCap(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())
	if err := b.waitForApproval(&missionBinding{ctx: context.Background()}, "r", time.Second); err == nil {
		t.Error("a binding with no World waited")
	}
	ctx, cancel := context.WithCancel(context.Background())
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	requestApproval(t, eng, "req-cap")
	b.approvalPoll = time.Millisecond
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if err := b.waitForApproval(&missionBinding{ctx: ctx, tenant: "acme", eng: eng}, "req-cap", 0); err == nil ||
		!strings.Contains(err.Error(), "ended") {
		t.Errorf("err = %v, want the end of the mission", err)
	}
}
