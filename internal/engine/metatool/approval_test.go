// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

// fakeGate is an approval queue with a fixed answer for each argument hash.
type fakeGate struct {
	approved map[string]bool // by ArgsHash, spent on use
	denied   map[string]bool
	asked    []ApprovalRequest
	err      error
}

func (g *fakeGate) Acquire(_ context.Context, r ApprovalRequest) (ApprovalState, string, error) {
	g.asked = append(g.asked, r)
	switch {
	case g.err != nil:
		return 0, "", g.err
	case g.denied[r.ArgsHash]:
		return ApprovalStateDenied, "req-" + r.ArgsHash, nil
	case g.approved[r.ArgsHash]:
		delete(g.approved, r.ArgsHash)
		return ApprovalStateApproved, "req-" + r.ArgsHash, nil
	}
	return ApprovalStatePending, "req-" + r.ArgsHash, nil
}

// responseMarks marks isolate_host and names its undo. The connector declares
// response actions, so the tools that it does not name are marked too.
func responseMarks(connector, tool string) componentcatalog.ToolApproval {
	if connector != "edr" {
		return componentcatalog.ToolApproval{}
	}
	switch tool {
	case "revoke_session":
		return componentcatalog.ToolApproval{Required: false}
	case "isolate_host":
		return componentcatalog.ToolApproval{Required: true, UndoTool: "release_host", BlastRadius: "one host"}
	}
	return componentcatalog.ToolApproval{Required: true}
}

func gatedCall(h *Handler, obs *seqObserver, id string, args map[string]any) (any, error) {
	return h.Call(context.Background(), Call{
		Caller: callerAlice, ID: id, Args: args, MissionID: "m1", Observer: obs, Recorder: obs.record,
	})
}

func newGatedHandler(q *seqQuerier, gate ApprovalGate) *Handler {
	return NewHandler(nil, allowAll("mcp:edr:isolate_host", "mcp:edr:release_host", "mcp:edr:revoke_session", "mcp:edr:new_tool"), q).
		WithApprovalGate(gate).WithApprovalMarks(responseMarks)
}

// A marked call with no approval never reaches the connector.
func TestCall_AMarkedCallWithNoApprovalNeverReachesTheConnector(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{}
	h := newGatedHandler(q, gate)

	_, err := gatedCall(h, obs, "mcp:edr:isolate_host", map[string]any{"host": "a"})
	if !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("want pending authorization, got %v", err)
	}
	if q.calls != 0 {
		t.Fatalf("the connector got %d calls", q.calls)
	}
	if len(gate.asked) != 1 || !strings.Contains(gate.asked[0].BlastRadius, "host=a") || gate.asked[0].Reversible != true {
		t.Fatalf("the request lacks the call data: %+v", gate.asked)
	}
}

// With no queue, a marked call is refused (fail closed).
func TestCall_AMarkedCallWithNoQueueIsRefused(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := newGatedHandler(q, nil)
	_, err := gatedCall(h, obs, "mcp:edr:isolate_host", nil)
	if !errors.Is(err, ErrApprovalUnavailable) || q.calls != 0 {
		t.Fatalf("want a refusal, got %v with %d calls", err, q.calls)
	}
}

// A queue error stops the call.
func TestCall_AQueueErrorStopsTheCall(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := newGatedHandler(q, &fakeGate{err: errors.New("store down")})
	if _, err := gatedCall(h, obs, "mcp:edr:isolate_host", nil); err == nil || q.calls != 0 {
		t.Fatalf("want an error and no call, got %v and %d", err, q.calls)
	}
}

// An approval for call A does not release call B.
func TestCall_AnApprovalForOneCallDoesNotReleaseAnother(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	argsA := map[string]any{"host": "a"}
	gate := &fakeGate{approved: map[string]bool{ArgsHash(argsA): true}}
	h := newGatedHandler(q, gate)

	if _, err := gatedCall(h, obs, "mcp:edr:isolate_host", map[string]any{"host": "b"}); !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("call B must wait, got %v", err)
	}
	if q.calls != 0 {
		t.Fatal("call B reached the connector")
	}
	if _, err := gatedCall(h, obs, "mcp:edr:isolate_host", argsA); err != nil {
		t.Fatalf("call A has an approval: %v", err)
	}
	if q.calls != 1 {
		t.Fatalf("call A must run once, got %d", q.calls)
	}
	// The approval is spent.
	if _, err := gatedCall(h, obs, "mcp:edr:isolate_host", argsA); !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("a second call A needs a new approval, got %v", err)
	}
	if q.calls != 1 {
		t.Fatalf("a second call A reached the connector: %d", q.calls)
	}
}

func TestCall_ADeniedCallReturnsDenied(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	args := map[string]any{"host": "a"}
	h := newGatedHandler(q, &fakeGate{denied: map[string]bool{ArgsHash(args): true}})
	_, err := gatedCall(h, obs, "mcp:edr:isolate_host", args)
	if !errors.Is(err, ErrApprovalDenied) || q.calls != 0 {
		t.Fatalf("want denied, got %v with %d calls", err, q.calls)
	}
}

// The mark decides: a session revoke runs with the grant alone, and a tool that
// the manifest does not name waits for approval.
func TestCall_TheManifestMarkDecidesTheGate(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{}
	h := newGatedHandler(q, gate)

	if _, err := gatedCall(h, obs, "mcp:edr:revoke_session", nil); err != nil {
		t.Fatalf("an unmarked tool needs only the grant: %v", err)
	}
	if len(gate.asked) != 0 {
		t.Fatal("an unmarked tool went to the approval queue")
	}
	if _, err := gatedCall(h, obs, "mcp:edr:new_tool", nil); !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("a tool that the manifest does not name must wait: %v", err)
	}
}

// A connector that only reads: no tool is marked, so the grant is enough. This
// uses the catalog of the platform, not a fake.
func TestCall_AToolOfAReadOnlyConnectorNeedsOnlyTheGrant(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{}
	h := NewHandler(nil, allowAll("mcp:crowdstrike-falcon:falcon_search_detections"), q).WithApprovalGate(gate)

	if _, err := gatedCall(h, obs, "mcp:crowdstrike-falcon:falcon_search_detections", nil); err != nil {
		t.Fatalf("a read-only connector needs only the grant: %v", err)
	}
	if q.calls != 1 || len(gate.asked) != 0 {
		t.Fatalf("calls %d, asked %d", q.calls, len(gate.asked))
	}
}

// The agent cannot select the gate: a call that is not granted never reaches
// the queue, and an unknown connector gets the strict rule.
func TestCall_TheGrantComesBeforeTheQueue(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{}
	h := NewHandler(nil, allowAll(), q).WithApprovalGate(gate).WithApprovalMarks(responseMarks)
	if _, err := gatedCall(h, obs, "mcp:edr:isolate_host", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if len(gate.asked) != 0 {
		t.Fatal("a call with no grant created a request")
	}
	if !componentcatalog.LookupToolApproval("no-such-connector", "t").Required {
		t.Fatal("a connector that the catalog does not list must get the strict rule")
	}
}

func TestArgsHash_IsStableAndSeparates(t *testing.T) {
	a := ArgsHash(map[string]any{"x": 1, "y": map[string]any{"b": 2, "a": 1}})
	b := ArgsHash(map[string]any{"y": map[string]any{"a": 1, "b": 2}, "x": 1})
	if a != b {
		t.Fatal("the order of keys changed the hash")
	}
	if ArgsHash(nil) != ArgsHash(map[string]any{}) {
		t.Fatal("nil and empty arguments must hash the same")
	}
	if a == ArgsHash(map[string]any{"x": 2, "y": map[string]any{"a": 1, "b": 2}}) {
		t.Fatal("a changed value kept the hash")
	}
}
