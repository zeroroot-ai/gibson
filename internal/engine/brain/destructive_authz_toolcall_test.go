// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func toolReq(mission, args string) ToolCallRequest {
	return ToolCallRequest{
		MissionID: mission, Agent: "agent-a", Connector: "edr", Tool: "isolate_host", ArgsHash: args,
		BlastRadius: "one host", Reversibility: ReversibilityIrreversible,
	}
}

// decideAndWait records a decision and waits until the World holds it. The
// fold is asynchronous.
func decideAndWait(t *testing.T, e *Engine, q *DestructiveAuthorizationQueue, id string, approved bool) {
	t.Helper()
	if err := q.Decide(id, "alice", approved); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	awaitDestructiveActionDecided(t, e, id)
}

func mustAuthorize(t *testing.T, q *DestructiveAuthorizationQueue, req ToolCallRequest) (state ToolCallState, id string) {
	t.Helper()
	state, id, err := q.AuthorizeToolCall(context.Background(), "acme", req)
	if err != nil {
		t.Fatalf("AuthorizeToolCall: %v", err)
	}
	return state, id
}

// A call with no decision records one request, however often it repeats.
func TestAuthorizeToolCall_PendingRecordsTheRequestOnce(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := e.DestructiveAuthorizationQueue()
	st1, id1 := mustAuthorize(t, q, toolReq("m1", "h1"))
	st2, id2 := mustAuthorize(t, q, toolReq("m1", "h1"))
	if st1 != ToolCallPending || st2 != ToolCallPending || id1 != id2 {
		t.Fatalf("want one pending request, got %v %q and %v %q", st1, id1, st2, id2)
	}
	pending := q.Pending()
	if len(pending) != 1 {
		t.Fatalf("want 1 pending request, got %+v", pending)
	}
	p := pending[0]
	if p.ActionKind != ActionKindToolCall || p.Connector != "edr" || p.Tool != "isolate_host" ||
		p.BlastRadius != "one host" || p.Reversibility != ReversibilityIrreversible || p.MissionID != "m1" {
		t.Fatalf("the request does not carry the call: %+v", p)
	}
}

// One approval releases the call one time. The next equal call needs a new
// approval.
func TestAuthorizeToolCall_AnApprovalReleasesOneCall(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := e.DestructiveAuthorizationQueue()
	_, id := mustAuthorize(t, q, toolReq("m1", "h1"))
	decideAndWait(t, e, q, id, true)
	if st, _ := mustAuthorize(t, q, toolReq("m1", "h1")); st != ToolCallApproved {
		t.Fatalf("the approved call must run, got %v", st)
	}
	st, id2 := mustAuthorize(t, q, toolReq("m1", "h1"))
	if st != ToolCallPending || id2 == id {
		t.Fatalf("a second equal call needs a new approval, got %v %q", st, id2)
	}
}

// An approval of call A does not release call B: another target, another tool
// and another mission each start their own request.
func TestAuthorizeToolCall_AnApprovalDoesNotReleaseAnotherCall(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := e.DestructiveAuthorizationQueue()
	_, id := mustAuthorize(t, q, toolReq("m1", "host-a"))
	decideAndWait(t, e, q, id, true)

	other := toolReq("m1", "host-b")
	otherTool := toolReq("m1", "host-a")
	otherTool.Tool = "disable_account"
	otherMission := toolReq("m2", "host-a")
	otherAgent := toolReq("m1", "host-a")
	otherAgent.Agent = "agent-b" // another agent of the mission cannot spend it (review m16)
	for name, req := range map[string]ToolCallRequest{
		"target": other, "tool": otherTool, "mission": otherMission, "agent": otherAgent,
	} {
		if st, _ := mustAuthorize(t, q, req); st != ToolCallPending {
			t.Errorf("an approval of call A released a call with another %s: %v", name, st)
		}
	}
	// Call A is still approved and unspent.
	if st, _ := mustAuthorize(t, q, toolReq("m1", "host-a")); st != ToolCallApproved {
		t.Fatalf("call A lost its approval: %v", st)
	}
}

// Another tenant has its own queue, and the key holds the tenant.
func TestToolCallKey_CoversEachPart(t *testing.T) {
	base := ToolCallKey("acme", "m1", "agent-a", "edr", "isolate_host", "h1")
	for name, key := range map[string]string{
		"tenant":    ToolCallKey("other", "m1", "agent-a", "edr", "isolate_host", "h1"),
		"mission":   ToolCallKey("acme", "m2", "agent-a", "edr", "isolate_host", "h1"),
		"agent":     ToolCallKey("acme", "m1", "agent-b", "edr", "isolate_host", "h1"), // review m16
		"connector": ToolCallKey("acme", "m1", "agent-a", "idp", "isolate_host", "h1"),
		"tool":      ToolCallKey("acme", "m1", "agent-a", "edr", "release_host", "h1"),
		"args":      ToolCallKey("acme", "m1", "agent-a", "edr", "isolate_host", "h2"),
		// A shifted boundary must not give the same key.
		"boundary": ToolCallKey("acme", "m1e", "agent-a", "dr", "isolate_host", "h1"),
	} {
		if key == base {
			t.Errorf("the key does not cover the %s", name)
		}
	}
}

func TestAuthorizeToolCall_ADenialIsFinal(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := e.DestructiveAuthorizationQueue()
	_, id := mustAuthorize(t, q, toolReq("m1", "h1"))
	decideAndWait(t, e, q, id, false)
	for range 2 {
		if st, _ := mustAuthorize(t, q, toolReq("m1", "h1")); st != ToolCallDenied {
			t.Fatalf("want denied, got %v", st)
		}
	}
	if err := q.Decide(id, "bob", true); err == nil {
		t.Fatal("a second decision must be refused")
	}
}

// Two equal calls at the same time spend one approval once.
func TestAuthorizeToolCall_ConcurrentCallsSpendOneApprovalOnce(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := e.DestructiveAuthorizationQueue()
	_, id := mustAuthorize(t, q, toolReq("m1", "h1"))
	decideAndWait(t, e, q, id, true)
	const n = 8
	var mu sync.Mutex
	approved := 0
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _, err := q.AuthorizeToolCall(context.Background(), "acme", toolReq("m1", "h1"))
			if err == nil && st == ToolCallApproved {
				mu.Lock()
				approved++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if approved != 1 {
		t.Fatalf("one approval released %d calls", approved)
	}
}

// A tool call and a proof share the queue. Neither can take the place of the
// other.
func TestAuthorizeToolCall_AProofCannotTakeTheIdentityOfACall(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := e.DestructiveAuthorizationQueue()
	_, id := mustAuthorize(t, q, toolReq("m1", "h1"))
	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: id}); err == nil ||
		!strings.Contains(err.Error(), "reserved prefix") {
		t.Fatalf("a proof request with a call id must be refused, got %v", err)
	}
	// An approved call does not approve a proof for the same id.
	decideAndWait(t, e, q, id, true)
	_, err := q.Verify(context.Background(), "", BetSettlementRequest{HypothesisID: id})
	if !errors.Is(err, ErrDestructiveActionPending) {
		t.Fatalf("Verify must not read a tool call record, got %v", err)
	}
}

func TestAuthorizeToolCall_NeedsTheCallParts(t *testing.T) {
	q := newDestructiveAuthzTestEngine(t).DestructiveAuthorizationQueue()
	if _, _, err := q.AuthorizeToolCall(context.Background(), "acme", ToolCallRequest{}); err == nil {
		t.Fatal("an empty request must be refused")
	}
}

// A restart keeps the request, the decision and the spent approval.
func TestToolCall_StateSurvivesARestart(t *testing.T) {
	w := NewWorld("t")
	key := ToolCallKey("acme", "m1", "agent-a", "edr", "isolate_host", "h1")
	id := toolCallIDPrefix + key + "#0"
	Reduce(w, DestructiveActionRequested{
		HypothesisID: id, Tenant: "acme", MissionID: "m1", ActionKind: ActionKindToolCall, CallKey: key,
		Connector: "edr", Tool: "isolate_host", ArgsHash: "h1", RequestedAtUnixMS: 1,
	})
	Reduce(w, DestructiveActionDecided{HypothesisID: id, Approved: true, UserID: "alice", DecidedAtUnixMS: 2})
	Reduce(w, DestructiveActionConsumed{HypothesisID: id, ConsumedAtUnixMS: 3})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := restored.DestructiveActionSnapshot()
	if !reflect.DeepEqual(got, w.DestructiveActionSnapshot()) {
		t.Fatalf("the record did not round-trip:\n got %+v\nwant %+v", got, w.DestructiveActionSnapshot())
	}
	if len(got) != 1 || !got[0].Consumed {
		t.Fatalf("the spent approval was lost: %+v", got)
	}
}

// A consumed event spends only an approved tool call.
func TestDestructiveActionConsumed_SpendsOnlyAnApprovedCall(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1"})
	Reduce(w, DestructiveActionDecided{HypothesisID: "hyp-1", Approved: true})
	Reduce(w, DestructiveActionConsumed{HypothesisID: "hyp-1"})
	Reduce(w, DestructiveActionRequested{HypothesisID: "call-1", ActionKind: ActionKindToolCall})
	Reduce(w, DestructiveActionConsumed{HypothesisID: "call-1"})
	for _, a := range w.DestructiveActionSnapshot() {
		if a.Consumed {
			t.Errorf("%q was spent: %+v", a.HypothesisID, a)
		}
	}
}

func TestDestructiveActionConsumed_Kind(t *testing.T) {
	if got := (DestructiveActionConsumed{}).Kind(); got != "destructive_action.consumed" {
		t.Fatalf("Kind() = %q", got)
	}
}
