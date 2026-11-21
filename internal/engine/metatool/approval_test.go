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
	// granted holds the merge requests with a merge slot, by tenant and key.
	granted map[string]bool
	merges  []string
}

func (g *fakeGate) MayMerge(_ context.Context, tenant, _, mr string) (bool, error) {
	g.merges = append(g.merges, tenant+"/"+mr)
	if g.err != nil {
		return false, g.err
	}
	return g.granted[tenant+"/"+mr], nil
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

// mergeMarks gives the merge role to forge:merge_merge_request. The second
// marked tool needs the role and an approval.
func mergeMarks(connector, tool string) componentcatalog.ToolApproval {
	if connector != "forge" {
		return componentcatalog.ToolApproval{}
	}
	switch tool {
	case "merge_merge_request":
		return componentcatalog.ToolApproval{Merge: true}
	case "force_merge":
		return componentcatalog.ToolApproval{Merge: true, Required: true}
	case "revert_merge_request":
		return componentcatalog.ToolApproval{DaemonOnly: true}
	}
	return componentcatalog.ToolApproval{}
}

func newMergeHandler(q *seqQuerier, gate ApprovalGate) *Handler {
	return NewHandler(nil, allowAll("mcp:forge:merge_merge_request", "mcp:forge:force_merge", "mcp:forge:get_mr",
		"mcp:forge:revert_merge_request"), q).
		WithApprovalGate(gate).WithApprovalMarks(mergeMarks)
}

// A merge with no slot in the World never reaches the connector, whatever the
// agent says (gibson#1458).
func TestCall_AMergeWithNoSlotNeverReachesTheConnector(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{granted: map[string]bool{"other/mr-1": true}}
	h := newMergeHandler(q, gate)
	cases := map[string]map[string]any{
		"no slot":               {"merge_request": "mr-1", "granted": true},
		"no merge request":      {"granted": true},
		"merge request no text": {"merge_request": 7},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := gatedCall(h, obs, "mcp:forge:merge_merge_request", args)
			if !errors.Is(err, ErrMergeNotGranted) {
				t.Fatalf("want merge not granted, got %v", err)
			}
		})
	}
	if q.calls != 0 {
		t.Fatalf("the connector got %d calls", q.calls)
	}
	// The slot of another tenant is not the slot of this one.
	if len(gate.merges) != 1 || gate.merges[0] != "acme/mr-1" {
		t.Fatalf("the gate was asked %v", gate.merges)
	}
}

// A tool with the role "daemon" runs only on the governed path of the
// daemon. An agent call never reaches the connector (review M7).
func TestCall_ADaemonToolRefusesAnAgent(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := newMergeHandler(q, &fakeGate{})
	_, err := gatedCall(h, obs, "mcp:forge:revert_merge_request", map[string]any{"merge_request": "mr-1"})
	if !errors.Is(err, ErrDaemonOnly) || !errors.Is(err, ErrBlocked) {
		t.Fatalf("an agent call: err = %v, want ErrDaemonOnly", err)
	}
	if q.calls != 0 {
		t.Fatalf("the connector got %d calls", q.calls)
	}
	_, err = h.Call(context.Background(), Call{
		Caller: callerAlice, ID: "mcp:forge:revert_merge_request", Args: map[string]any{"merge_request": "mr-1"},
		MissionID: "m1", Observer: obs, Recorder: obs.record, Daemon: true,
	})
	if err != nil || q.calls != 1 {
		t.Fatalf("a daemon call: err = %v, calls = %d", err, q.calls)
	}
}

// A merge with a slot runs, and a tool with no role needs only the grant.
func TestCall_AMergeWithASlotRuns(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{granted: map[string]bool{"acme/mr-1": true}}
	h := newMergeHandler(q, gate)
	if _, err := gatedCall(h, obs, "mcp:forge:merge_merge_request", map[string]any{"merge_request": " mr-1 "}); err != nil {
		t.Fatalf("a merge with a slot: %v", err)
	}
	if _, err := gatedCall(h, obs, "mcp:forge:get_mr", nil); err != nil {
		t.Fatalf("a tool with no role: %v", err)
	}
	if q.calls != 2 || len(gate.merges) != 1 {
		t.Fatalf("calls = %d, merge checks = %v", q.calls, gate.merges)
	}
}

// A merge that waits for its slot does not spend an approval, and the merge
// role with no gate is refused (fail closed).
func TestCall_TheMergeSlotComesBeforeTheApproval(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	gate := &fakeGate{approved: map[string]bool{}}
	h := newMergeHandler(q, gate)
	if _, err := gatedCall(h, obs, "mcp:forge:force_merge", map[string]any{"merge_request": "mr-1"}); !errors.Is(err, ErrMergeNotGranted) {
		t.Fatalf("want merge not granted, got %v", err)
	}
	if len(gate.asked) != 0 {
		t.Fatalf("the approval queue was asked before the slot: %+v", gate.asked)
	}
	if _, err := gatedCall(newMergeHandler(q, nil), obs, "mcp:forge:merge_merge_request", map[string]any{"merge_request": "mr-1"}); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("want a refusal with no gate, got %v", err)
	}
	if q.calls != 0 {
		t.Fatalf("the connector got %d calls", q.calls)
	}
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
