// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

type countingConnector struct{ calls []map[string]any }

func (c *countingConnector) CallConnectorTool(_ context.Context, _, _, _ string, args map[string]any) (any, error) {
	c.calls = append(c.calls, args)
	return map[string]any{"ok": true}, nil
}

type allowAllAuthz struct{}

func (allowAllAuthz) CanExecute(context.Context, catalog.Caller, toolid.ID) (bool, error) {
	return true, nil
}

type nopObserver struct{}

func (nopObserver) Intent(context.Context, metatool.CallRecord) error          { return nil }
func (nopObserver) Result(context.Context, metatool.CallRecord, []byte, error) {}

// The path from invoke_tool to the approval queue of ADR-0132 with the real
// brain engine: the request shows in the queue, a decision releases one call,
// and a different call stays closed.
func TestToolApproval_InvokeToolThroughTheRealQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	registry := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := registry.For("acme")
	queue := eng.DestructiveAuthorizationQueue()

	conn := &countingConnector{}
	h := metatool.NewHandler(nil, allowAllAuthz{}, conn).
		WithApprovalGate(newTenantRoutedToolApproval(registry)).
		WithApprovalMarks(func(_, tool string) componentcatalog.ToolApproval {
			if tool == "isolate_host" {
				return componentcatalog.ToolApproval{Required: true, UndoTool: "release_host", BlastRadius: "one host"}
			}
			return componentcatalog.ToolApproval{}
		})
	call := func(tool string, args map[string]any) error {
		_, err := h.Call(ctx, metatool.Call{
			Caller: catalog.Caller{Subject: "agent", Tenant: "acme"}, ID: "mcp:edr:" + tool, Args: args,
			MissionID: "m1",
			Observer:  nopObserver{},
			Recorder:  func(context.Context, metatool.CallRecord, []byte, string) string { return "" },
		})
		if err != nil {
			return fmt.Errorf("call %s: %w", tool, err)
		}
		return nil
	}
	isolateA := map[string]any{"host": "a"}

	if err := call("isolate_host", isolateA); !errors.Is(err, metatool.ErrApprovalPending) {
		t.Fatalf("want pending authorization, got %v", err)
	}
	if len(conn.calls) != 0 {
		t.Fatal("the connector got a call with no approval")
	}
	pending := queue.Pending()
	if len(pending) != 1 {
		t.Fatalf("want one request in the queue, got %+v", pending)
	}
	if pending[0].Reversibility != brain.ReversibilityReversible || pending[0].Technique != "mcp:edr:isolate_host" {
		t.Fatalf("the request lacks the manifest data: %+v", pending[0])
	}

	// An unmarked tool needs only the grant.
	if err := call("revoke_session", nil); err != nil {
		t.Fatalf("an unmarked tool: %v", err)
	}

	if err := queue.Decide(pending[0].HypothesisID, "alice", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(queue.Pending()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Another target does not use the approval.
	if err := call("isolate_host", map[string]any{"host": "b"}); !errors.Is(err, metatool.ErrApprovalPending) {
		t.Fatalf("call B must wait, got %v", err)
	}
	before := len(conn.calls)
	if err := call("isolate_host", isolateA); err != nil {
		t.Fatalf("the approved call: %v", err)
	}
	if len(conn.calls) != before+1 {
		t.Fatal("the approved call did not run once")
	}
	if err := call("isolate_host", isolateA); !errors.Is(err, metatool.ErrApprovalPending) {
		t.Fatalf("the approval is spent, got %v", err)
	}
	if len(conn.calls) != before+1 {
		t.Fatal("a second call ran on one approval")
	}
}

// A call of another tenant reaches only its own queue.
func TestToolApproval_NeedsATenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	gate := newTenantRoutedToolApproval(brain.NewRegistry(ctx, braintest.StoreFactory()))
	if _, _, err := gate.Acquire(ctx, metatool.ApprovalRequest{Connector: "c", Tool: "t", ArgsHash: "h"}); err == nil {
		t.Fatal("a call with no tenant must fail")
	}
}

// The merge gate reads the merge slot from the World of the real brain engine
// (gibson#1458). A merge request with no slot gets no call. After the queue
// grants the slot, the same call runs.
func TestToolApproval_TheMergeGateReadsTheWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	registry := brain.NewRegistry(ctx, braintest.StoreFactory(), brain.MergeGateSystem)
	eng := registry.For("acme")

	conn := &countingConnector{}
	h := metatool.NewHandler(nil, allowAllAuthz{}, conn).
		WithApprovalGate(newTenantRoutedToolApproval(registry)).
		WithApprovalMarks(func(_, tool string) componentcatalog.ToolApproval {
			return componentcatalog.ToolApproval{Merge: tool == "merge_merge_request"}
		})
	mission := "m1"
	merge := func(tenant string) error {
		_, err := h.Call(ctx, metatool.Call{
			Caller: catalog.Caller{Subject: "agent", Tenant: tenant}, ID: "mcp:forge:merge_merge_request",
			Args: map[string]any{"merge_request": "mr-7"}, MissionID: mission,
			Observer: nopObserver{},
			Recorder: func(context.Context, metatool.CallRecord, []byte, string) string { return "" },
		})
		if err != nil {
			return fmt.Errorf("merge for %s: %w", tenant, err)
		}
		return nil
	}

	if err := merge("acme"); !errors.Is(err, metatool.ErrMergeNotGranted) {
		t.Fatalf("want merge not granted, got %v", err)
	}
	eng.Submit(brain.MergeRequestQueued{MergeRequest: "mr-7", Application: "app-1", At: time.Now().UTC(), MissionID: "m1"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var granted bool
		eng.ReadWorld(func(w *brain.World) { granted = w.MayMerge("mr-7") })
		if granted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(conn.calls) != 0 {
		t.Fatal("the connector got a call before the slot")
	}
	if err := merge("acme"); err != nil {
		t.Fatalf("the merge with a slot: %v", err)
	}
	if len(conn.calls) != 1 {
		t.Fatalf("connector calls = %d, want 1", len(conn.calls))
	}
	// The slot is bound to the merge request and not to a mission: a new mission
	// of the fix agent merges a granted merge request that another mission opened
	// (gibson#1609).
	mission = "a-later-pass-with-a-new-mission"
	if err := merge("acme"); err != nil {
		t.Fatalf("a new mission must merge a granted merge request: %v", err)
	}
	if len(conn.calls) != 2 {
		t.Fatalf("connector calls = %d, want 2", len(conn.calls))
	}
	// The gate records the allowed calls, so the watcher frees no slot that a
	// call is still using.
	var allowedAt time.Time
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		eng.ReadWorld(func(w *brain.World) {
			for _, sl := range w.MergeSlots() {
				allowedAt = sl.LastAllowedAt
			}
		})
		if !allowedAt.IsZero() {
			break
		}
	}
	if allowedAt.IsZero() {
		t.Fatal("the gate did not record the allowed merge call")
	}
	// The slot of one tenant is not the slot of another.
	if err := merge("other"); !errors.Is(err, metatool.ErrMergeNotGranted) {
		t.Fatalf("another tenant: want merge not granted, got %v", err)
	}
}

// The race of the intake queue: the gate reads the slot as granted, and then the
// release of the watcher is folded before the call is recorded. The gate must
// refuse the call. It must not let the merge go to the host with a slot that is
// gone, and the Application must not get a second slot for a second merge
// (gibson#1609).
func TestToolApproval_AReleaseFoldedBeforeTheCallRefusesTheMerge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	registry := brain.NewRegistry(ctx, braintest.StoreFactory(), brain.MergeGateSystem)
	eng := registry.For("acme")
	gate := newTenantRoutedToolApproval(registry)

	now := time.Now().UTC()
	eng.Submit(brain.MergeRequestQueued{MergeRequest: "mr-1", Application: "app-1", At: now, MissionID: "m1"})
	eng.Submit(brain.MergeRequestQueued{MergeRequest: "mr-2", Application: "app-1", At: now.Add(time.Second), MissionID: "m2"})
	waitFor := func(cond func(w *brain.World) bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			var ok bool
			eng.ReadWorld(func(w *brain.World) { ok = cond(w) })
			if ok {
				return
			}
		}
		t.Fatal("the World did not reach the state in time")
	}
	waitFor(func(w *brain.World) bool { return w.MayMerge("mr-1") })

	// The release of the watcher is folded after the gate read the slot and before
	// the gate records the call.
	gate.betweenReadAndRecord = func(e *brain.Engine) {
		release := brain.MergeSlotExpired{
			MergeRequest: "mr-1", Application: "app-1", At: time.Now().UTC(), CallBound: 2 * time.Minute,
		}
		if err := e.SubmitAndWait(ctx, release); err != nil {
			t.Errorf("release: %v", err)
		}
	}
	ok, err := gate.MayMerge(ctx, "acme", "mr-1")
	if err != nil {
		t.Fatalf("MayMerge: %v", err)
	}
	if ok {
		t.Fatal("the gate allowed a merge for a slot that the release had already freed")
	}

	// The other fix gets the slot after the first one is gone, and only one slot
	// of the Application is granted.
	waitFor(func(w *brain.World) bool { return w.MayMerge("mr-2") })
	eng.ReadWorld(func(w *brain.World) {
		granted := 0
		for _, sl := range w.MergeSlots() {
			if sl.Granted {
				granted++
			}
			if sl.MergeRequest == "mr-1" {
				t.Errorf("the freed slot of mr-1 is back: %+v", sl)
			}
		}
		if granted != 1 {
			t.Errorf("granted slots = %d, want 1", granted)
		}
	})

	// A release that comes after the call is held back by the reducer.
	gate.betweenReadAndRecord = nil
	ok, err = gate.MayMerge(ctx, "acme", "mr-2")
	if err != nil || !ok {
		t.Fatalf("MayMerge of the granted slot = %v, %v; want true", ok, err)
	}
	if err := eng.SubmitAndWait(ctx, brain.MergeSlotExpired{
		MergeRequest: "mr-2", Application: "app-1", At: time.Now().UTC(), CallBound: 2 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	eng.ReadWorld(func(w *brain.World) {
		if !w.MayMerge("mr-2") {
			t.Error("a release after an allowed call freed the slot")
		}
	})
}

func grantedGateFixture(t *testing.T) (context.Context, *tenantRoutedToolApproval, *brain.Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	registry := brain.NewRegistry(ctx, braintest.StoreFactory(), brain.MergeGateSystem)
	eng := registry.For("acme")
	eng.Submit(brain.MergeRequestQueued{MergeRequest: "mr-1", Application: "app-1", At: time.Now().UTC(), MissionID: "m1"})
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var ok bool
		eng.ReadWorld(func(w *brain.World) { ok = w.MayMerge("mr-1") })
		if ok {
			return ctx, newTenantRoutedToolApproval(registry), eng
		}
	}
	t.Fatal("the slot was not granted in time")
	return nil, nil, nil
}

// A record that fails or times out is "unavailable": the agent retries within merge_wait. They are not a final
// refusal (gibson#1609).
func TestToolApproval_AFailedRecordOrAMissingWorldIsUnavailable(t *testing.T) {
	ctx, gate, _ := grantedGateFixture(t)
	gate.recordCall = func(context.Context, *brain.Engine, brain.Event) error { return context.DeadlineExceeded }
	_, err := gate.MayMerge(ctx, "acme", "mr-1")
	if !errors.Is(err, metatool.ErrApprovalUnavailable) {
		t.Fatalf("a failed record gave %v, want ErrApprovalUnavailable", err)
	}

	// The handler maps it the same way, so the harness answers UNAVAILABLE.
	conn := &countingConnector{}
	h := metatool.NewHandler(nil, allowAllAuthz{}, conn).
		WithApprovalGate(gate).
		WithApprovalMarks(func(_, tool string) componentcatalog.ToolApproval {
			return componentcatalog.ToolApproval{Merge: tool == "merge_merge_request"}
		})
	_, err = h.Call(ctx, metatool.Call{
		Caller: catalog.Caller{Subject: "agent", Tenant: "acme"}, ID: "mcp:forge:merge_merge_request",
		Args: map[string]any{"merge_request": "mr-1"}, MissionID: "m1",
		Observer: nopObserver{},
		Recorder: func(context.Context, metatool.CallRecord, []byte, string) string { return "" },
	})
	if !errors.Is(err, metatool.ErrApprovalUnavailable) {
		t.Fatalf("the merge call gave %v, want ErrApprovalUnavailable", err)
	}
	if len(conn.calls) != 0 {
		t.Fatal("the connector got a call although the record failed")
	}
}

// Two overlapping calls, or a clock that steps back, fold a later call first. The
// reducer keeps the later time, and the earlier call is still valid.
func TestToolApproval_ALaterCallFoldedFirstDoesNotRefuseTheEarlierOne(t *testing.T) {
	ctx, gate, _ := grantedGateFixture(t)
	gate.betweenReadAndRecord = func(e *brain.Engine) {
		later := brain.MergeCallAllowed{MergeRequest: "mr-1", At: time.Now().UTC().Add(time.Hour)}
		if err := e.SubmitAndWait(ctx, later); err != nil {
			t.Errorf("later call: %v", err)
		}
	}
	ok, err := gate.MayMerge(ctx, "acme", "mr-1")
	if err != nil || !ok {
		t.Fatalf("MayMerge = %v, %v; want true after a later call folded first", ok, err)
	}
}
