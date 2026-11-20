// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
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
		return err
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
	merge := func(tenant string) error {
		_, err := h.Call(ctx, metatool.Call{
			Caller: catalog.Caller{Subject: "agent", Tenant: tenant}, ID: "mcp:forge:merge_merge_request",
			Args: map[string]any{"merge_request": "mr-7"}, MissionID: "m1",
			Observer: nopObserver{},
			Recorder: func(context.Context, metatool.CallRecord, []byte, string) string { return "" },
		})
		return err
	}

	if err := merge("acme"); !errors.Is(err, metatool.ErrMergeNotGranted) {
		t.Fatalf("want merge not granted, got %v", err)
	}
	eng.Submit(brain.MergeRequestQueued{MergeRequest: "mr-7", Application: "app-1", At: time.Now().UTC()})
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
	// The slot of one tenant is not the slot of another.
	if err := merge("other"); !errors.Is(err, metatool.ErrMergeNotGranted) {
		t.Fatalf("another tenant: want merge not granted, got %v", err)
	}
}
