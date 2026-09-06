// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
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
}

func (h *toolHarness) CallToolProto(_ context.Context, name string, request proto.Message, response proto.Message) error {
	h.gotName = name
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
	eng := brain.NewEngine("tenant-a")
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
	b.register(req.MissionID, &missionBinding{ctx: context.Background(), eng: eng, harness: h})
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
