package daemon

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestWorldService_TenantScopedRead: the read path returns the caller's tenant's
// live World, and refuses a request with no tenant in context.
func TestWorldService_TenantScopedRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.ListHostsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.ListHosts(tctx, &worldpb.ListHostsRequest{}); err != nil {
			t.Fatalf("ListHosts: %v", err)
		}
		if len(resp.Hosts) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(resp.GetHosts()) != 1 || resp.Hosts[0].Address != "10.0.0.5" {
		t.Fatalf("ListHosts = %+v, want one host 10.0.0.5", resp.GetHosts())
	}

	// No tenant in context -> PermissionDenied.
	if _, err := srv.ListHosts(context.Background(), &worldpb.ListHostsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestWorldService_ListLlmCalls: the World's LLM-call provenance (gibson#755) is
// readable, tenant-scoped, with token data surfaced; no tenant -> PermissionDenied.
func TestWorldService_ListLlmCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.LlmCallObserved{
		CallID: "c1", Model: "claude-haiku-4-5", PromptTokens: 100, CompletionTokens: 40,
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.ListLlmCallsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.ListLlmCalls(tctx, &worldpb.ListLlmCallsRequest{}); err != nil {
			t.Fatalf("ListLlmCalls: %v", err)
		}
		if len(resp.LlmCalls) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(resp.GetLlmCalls()) != 1 {
		t.Fatalf("ListLlmCalls = %+v, want one call", resp.GetLlmCalls())
	}
	c := resp.LlmCalls[0]
	if c.Model != "claude-haiku-4-5" || c.PromptTokens != 100 || c.CompletionTokens != 40 {
		t.Fatalf("unexpected call view: %+v", c)
	}

	if _, err := srv.ListLlmCalls(context.Background(), &worldpb.ListLlmCallsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestWorldService_GetLlmCall: a single call's transcript (prompt + completion)
// is retrievable for the conversation view (gibson#755); unknown id -> NotFound.
func TestWorldService_GetLlmCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.LlmCallObserved{
		CallID:     "c1",
		Model:      "claude-haiku-4-5",
		Messages:   []brain.LlmMessage{{Role: "user", Content: "scan the host"}},
		Completion: "running nmap",
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.GetLlmCallResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = srv.GetLlmCall(tctx, &worldpb.GetLlmCallRequest{CallId: "c1"})
		if err == nil && resp.GetCall() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp.GetCall() == nil {
		t.Fatal("GetLlmCall returned no call")
	}
	call := resp.Call
	if len(call.Messages) != 1 || call.Messages[0].Content != "scan the host" || call.Completion != "running nmap" {
		t.Fatalf("transcript not returned: %+v", call)
	}

	// Unknown call id -> NotFound.
	if _, err := srv.GetLlmCall(tctx, &worldpb.GetLlmCallRequest{CallId: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound for unknown call, got %v", err)
	}
}

// TestWorldService_GetFrameAt: a replay frame is a server-side fold of the log to
// a point (ADR-0001). Scrubbing to an earlier seq reproduces the World as it was;
// seq == total reproduces the live World; isolation holds.
func TestWorldService_GetFrameAt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	// Three observations: host, then a finding, then a second host.
	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	reg.For("acme").Submit(brain.FindingRaised{ID: "f1", Title: "weak ssh", ScopeID: "s", Address: "10.0.0.5", Severity: "high"})
	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{443}})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	// Wait until all three events have folded into the live World.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Frame after the first event only: one host, no finding.
	f1, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 1})
	if err != nil {
		t.Fatalf("GetFrameAt(1): %v", err)
	}
	if f1.Seq != 1 || f1.Total != 3 {
		t.Fatalf("frame meta = seq %d/total %d, want 1/3", f1.Seq, f1.Total)
	}
	if len(f1.Hosts) != 1 || len(f1.Findings) != 0 {
		t.Fatalf("frame@1 = %d hosts %d findings, want 1/0", len(f1.Hosts), len(f1.Findings))
	}

	// Frame after two events: one host + the finding (the second host not yet seen).
	f2, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 2})
	if err != nil {
		t.Fatalf("GetFrameAt(2): %v", err)
	}
	if len(f2.Hosts) != 1 || len(f2.Findings) != 1 {
		t.Fatalf("frame@2 = %d hosts %d findings, want 1/1", len(f2.Hosts), len(f2.Findings))
	}

	// seq past the end clamps to total → the live World: two hosts + one finding.
	fEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99})
	if err != nil {
		t.Fatalf("GetFrameAt(99): %v", err)
	}
	if fEnd.Seq != 3 || len(fEnd.Hosts) != 2 || len(fEnd.Findings) != 1 {
		t.Fatalf("frame@end = seq %d, %d hosts %d findings, want 3/2/1", fEnd.Seq, len(fEnd.Hosts), len(fEnd.Findings))
	}

	// Folding a frame must not mutate the live World (still two hosts).
	if live, _ := srv.ListHosts(tctx, &worldpb.ListHostsRequest{}); len(live.GetHosts()) != 2 {
		t.Fatalf("live World mutated by frame fold: %d hosts, want 2", len(live.GetHosts()))
	}

	// No tenant -> error.
	if _, err := srv.GetFrameAt(context.Background(), &worldpb.GetFrameAtRequest{Seq: 1}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestWorldService_GetFrameAt_MissionScoped: a mission-scoped frame folds only that
// mission's slice of the Timeline (gibson#1060). At seq 0 / mid / total it
// materializes exactly that mission's World; another mission's events never bleed
// in; the no-mission call still returns the tenant-wide fold; isolation holds.
func TestWorldService_GetFrameAt_MissionScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	// Two interleaved missions plus one tenant-ambient host observation (an
	// observation carries no mission linkage, so it belongs to neither slice).
	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "goal A"})                                     // A slice: 1
	e.Submit(brain.MissionStarted{ID: "B", Goal: "goal B"})                                     // B slice: 1
	e.Submit(brain.WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "nmap"}) // A slice: 2
	e.Submit(brain.WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "tool", Target: "nmap"}) // B slice: 2
	e.Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})       // ambient
	e.Submit(brain.WorkCompleted{ID: "wa1", Result: "ok"})                                      // A slice: 3
	e.Submit(brain.WorkCompleted{ID: "wb1", Result: "ok"})                                      // B slice: 3

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	// Wait until all seven events have folded into the live World.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 7 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(reg.For("acme").Events()); got != 7 {
		t.Fatalf("timeline has %d events, want 7", got)
	}

	missionIDs := func(r *worldpb.GetFrameAtResponse) []string {
		var ids []string
		for _, m := range r.GetMissions() {
			ids = append(ids, m.Id)
		}
		return ids
	}

	// --- Mission A: scoped slice is exactly its 3 events. ---
	// seq 0: nothing folded yet.
	a0, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 0, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(0,A): %v", err)
	}
	if a0.Seq != 0 || a0.Total != 3 {
		t.Fatalf("frame@0/A meta = %d/%d, want 0/3", a0.Seq, a0.Total)
	}
	if len(a0.Missions) != 0 || len(a0.Hosts) != 0 || len(a0.Findings) != 0 {
		t.Fatalf("frame@0/A = %d missions %d hosts %d findings, want 0/0/0", len(a0.Missions), len(a0.Hosts), len(a0.Findings))
	}

	// mid (seq 1): mission A started; B must not appear.
	a1, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 1, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(1,A): %v", err)
	}
	if ids := missionIDs(a1); len(ids) != 1 || ids[0] != "A" {
		t.Fatalf("frame@1/A missions = %v, want [A]", ids)
	}

	// total (clamped past end): A's full slice; only mission A, no ambient host.
	aEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,A): %v", err)
	}
	if aEnd.Seq != 3 || aEnd.Total != 3 {
		t.Fatalf("frame@end/A meta = %d/%d, want 3/3", aEnd.Seq, aEnd.Total)
	}
	if ids := missionIDs(aEnd); len(ids) != 1 || ids[0] != "A" {
		t.Fatalf("frame@end/A missions = %v, want [A] (B bled in?)", ids)
	}
	if len(aEnd.Hosts) != 0 {
		t.Fatalf("frame@end/A = %d hosts, want 0 (ambient observation bled in?)", len(aEnd.Hosts))
	}

	// --- Mission B: symmetric isolation — only mission B. ---
	bEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "B"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,B): %v", err)
	}
	if ids := missionIDs(bEnd); len(ids) != 1 || ids[0] != "B" {
		t.Fatalf("frame@end/B missions = %v, want [B] (A bled in?)", ids)
	}

	// --- No mission: the tenant-wide fold is unchanged (both missions + ambient host). ---
	all, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99})
	if err != nil {
		t.Fatalf("GetFrameAt(99): %v", err)
	}
	if all.Seq != 7 || all.Total != 7 {
		t.Fatalf("frame@end meta = %d/%d, want 7/7", all.Seq, all.Total)
	}
	if ids := missionIDs(all); len(ids) != 2 || ids[0] != "A" || ids[1] != "B" {
		t.Fatalf("tenant-wide frame missions = %v, want [A B]", ids)
	}
	if len(all.Hosts) != 1 {
		t.Fatalf("tenant-wide frame = %d hosts, want 1 (the ambient host)", len(all.Hosts))
	}

	// GetTimeline mirrors the scoping so the Scroller's timeline length matches the
	// frame total: mission A sees 3 events, the tenant sees all 7.
	atl, err := srv.GetTimeline(tctx, &worldpb.GetTimelineRequest{MissionId: "A"})
	if err != nil {
		t.Fatalf("GetTimeline(A): %v", err)
	}
	if len(atl.GetEvents()) != 3 {
		t.Fatalf("GetTimeline(A) = %d events, want 3", len(atl.GetEvents()))
	}
	fulltl, err := srv.GetTimeline(tctx, &worldpb.GetTimelineRequest{})
	if err != nil {
		t.Fatalf("GetTimeline(): %v", err)
	}
	if len(fulltl.GetEvents()) != 7 {
		t.Fatalf("GetTimeline() = %d events, want 7", len(fulltl.GetEvents()))
	}

	// Isolation: no tenant in context -> denied, even with a mission set.
	if _, err := srv.GetFrameAt(context.Background(), &worldpb.GetFrameAtRequest{Seq: 1, MissionId: "A"}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestWorldService_GetFrameAt_MissionScoped_FindingsAndLlmCalls: a mission-scoped
// frame surfaces the component findings and ExecuteLLM-issued LLM calls a mission
// produced, at the tick they occurred (gibson#1078, the mission-evidence edge). A
// finding or call carrying no mission context (component finding outside a mission,
// dashboard chat) stays tenant-ambient — present in the tenant-wide fold but never
// in a mission frame — and one mission's evidence never bleeds into another's.
func TestWorldService_GetFrameAt_MissionScoped_FindingsAndLlmCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "goal A"})                                                          // A idx 0
	e.Submit(brain.FindingRaised{ID: "fa", Title: "RCE", Severity: "critical", MissionID: "A"})                      // A idx 1 (component path)
	e.Submit(brain.LlmCallObserved{CallID: "la", MissionID: "A", Model: "m", PromptTokens: 10, CompletionTokens: 5}) // A idx 2 (ExecuteLLM)
	// Mission B's evidence — must never bleed into A.
	e.Submit(brain.MissionStarted{ID: "B", Goal: "goal B"})
	e.Submit(brain.FindingRaised{ID: "fb", Title: "B finding", Severity: "high", MissionID: "B"})
	e.Submit(brain.LlmCallObserved{CallID: "lb", MissionID: "B", Model: "m", PromptTokens: 1, CompletionTokens: 1})
	// Tenant-ambient evidence — no mission context (component finding outside a
	// mission, dashboard chat) — belongs to no mission frame.
	e.Submit(brain.FindingRaised{ID: "fx", Title: "ambient finding", Severity: "low"})
	e.Submit(brain.LlmCallObserved{CallID: "lx", Model: "m", PromptTokens: 2, CompletionTokens: 2})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 8 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(reg.For("acme").Events()); got != 8 {
		t.Fatalf("timeline has %d events, want 8", got)
	}

	findingIDs := func(r *worldpb.GetFrameAtResponse) []string {
		var ids []string
		for _, f := range r.GetFindings() {
			ids = append(ids, f.GetId())
		}
		return ids
	}
	callIDs := func(r *worldpb.GetFrameAtResponse) []string {
		var ids []string
		for _, c := range r.GetLlmCalls() {
			ids = append(ids, c.GetCallId())
		}
		return ids
	}

	// seq 2 (mission A) folds A's slice [MissionStarted, FindingRaised fa]: the
	// finding has folded; the call (slice index 2) has not folded yet.
	a2, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 2, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(2,A): %v", err)
	}
	if ids := findingIDs(a2); len(ids) != 1 || ids[0] != "fa" {
		t.Fatalf("frame@2/A findings = %v, want [fa]", ids)
	}
	if ids := callIDs(a2); len(ids) != 0 {
		t.Fatalf("frame@2/A calls = %v, want none (call not folded yet)", ids)
	}

	// end (mission A): both A's finding and call; no B or ambient evidence.
	aEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,A): %v", err)
	}
	if ids := findingIDs(aEnd); len(ids) != 1 || ids[0] != "fa" {
		t.Fatalf("frame@end/A findings = %v, want [fa] (B/ambient bled in?)", ids)
	}
	if ids := callIDs(aEnd); len(ids) != 1 || ids[0] != "la" {
		t.Fatalf("frame@end/A calls = %v, want [la] (B/ambient bled in?)", ids)
	}

	// Tenant-wide fold (no mission): every finding and call, incl. the ambient ones.
	all, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99})
	if err != nil {
		t.Fatalf("GetFrameAt(99): %v", err)
	}
	if got := len(all.GetFindings()); got != 3 {
		t.Fatalf("tenant-wide findings = %d, want 3", got)
	}
	if got := len(all.GetLlmCalls()); got != 3 {
		t.Fatalf("tenant-wide calls = %d, want 3", got)
	}
}

// TestWorldService_GetFrameAt_Work: the rich frame (PRD #1059 M2, gibson#1061)
// surfaces a mission's WorkItems reconstructed as-of the folded tick. A work item
// appears at its dispatch tick (status "running" = in-flight) and clears the
// in-flight set at its completion tick (terminal status), and no other mission's
// work bleeds into a mission-scoped frame.
func TestWorldService_GetFrameAt_Work(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "goal A"})                                       // A idx 0
	e.Submit(brain.WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "nmap"})   // A idx 1
	e.Submit(brain.WorkDispatched{ID: "wa2", MissionID: "A", ItemKind: "agent", Target: "recon"}) // A idx 2
	e.Submit(brain.WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "tool", Target: "nmap"})   // mission B
	e.Submit(brain.WorkCompleted{ID: "wa1", Result: "ok"})                                        // A idx 3

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	inflight := func(r *worldpb.GetFrameAtResponse) []string {
		var ids []string
		for _, w := range r.GetWork() {
			if w.GetStatus() == "running" {
				ids = append(ids, w.GetId())
			}
		}
		sort.Strings(ids)
		return ids
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// seq 0: nothing dispatched yet.
	f0, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 0, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(0,A): %v", err)
	}
	if len(f0.GetWork()) != 0 {
		t.Fatalf("frame@0/A work = %+v, want none", f0.GetWork())
	}

	// seq 3: wa1 + wa2 dispatched (the first 3 events) — both in flight.
	f3, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 3, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(3,A): %v", err)
	}
	if got := inflight(f3); !eq(got, []string{"wa1", "wa2"}) {
		t.Fatalf("frame@3/A in-flight = %v, want [wa1 wa2]", got)
	}

	// total: wa1 completed → leaves the in-flight set; wa2 still running; mission B
	// work never appears; wa1 carried with terminal status.
	fEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,A): %v", err)
	}
	if got := inflight(fEnd); !eq(got, []string{"wa2"}) {
		t.Fatalf("frame@end/A in-flight = %v, want [wa2] (wa1 should have cleared)", got)
	}
	for _, w := range fEnd.GetWork() {
		if w.GetId() == "wb1" {
			t.Fatal("mission B work bled into mission A frame")
		}
		if w.GetMissionId() != "A" {
			t.Fatalf("frame@end/A work %q has mission_id %q, want A", w.GetId(), w.GetMissionId())
		}
		if w.GetId() == "wa1" && w.GetStatus() != "done" {
			t.Fatalf("wa1 status = %q, want done", w.GetStatus())
		}
		if w.GetId() == "wa2" && w.GetKind() != "agent" {
			t.Fatalf("wa2 kind = %q, want agent", w.GetKind())
		}
	}
}

// TestWorldService_GetFrameAt_Decisions: the rich frame (PRD #1059 M2, gibson#1062)
// surfaces a mission's Decider decisions reconstructed as-of the folded tick. A
// decision appears at its request tick (status "pending" = in flight), gains the
// work it chose to dispatch, and reaches "completed" at its completion tick —
// carrying the mission completion as rationale where it ended the mission. No other
// mission's decisions bleed into a mission-scoped frame.
func TestWorldService_GetFrameAt_Decisions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "goal A"})                                        // A idx 0
	e.Submit(brain.DecisionRequested{MissionID: "A", Cursor: 0})                                   // A idx 1: open A#d1
	e.Submit(brain.WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "nmap"})    // A idx 2: A#d1 chose wa1
	e.Submit(brain.DecisionCompleted{MissionID: "A"})                                              // A idx 3: A#d1 completed
	e.Submit(brain.DecisionRequested{MissionID: "A", Cursor: 1})                                   // A idx 4: open A#d2
	e.Submit(brain.MissionDone{ID: "A", Outcome: brain.MissionCompleted, Reason: "goal resolved"}) // A idx 5
	e.Submit(brain.DecisionCompleted{MissionID: "A"})                                              // A idx 6: A#d2 completed
	e.Submit(brain.DecisionRequested{MissionID: "B", Cursor: 0})                                   // mission B (excluded)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 8 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	ids := func(r *worldpb.GetFrameAtResponse) []string {
		var out []string
		for _, d := range r.GetDecisions() {
			out = append(out, d.GetId()+"/"+d.GetStatus())
		}
		sort.Strings(out)
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// seq 0: no decision requested yet.
	f0, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 0, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(0,A): %v", err)
	}
	if len(f0.GetDecisions()) != 0 {
		t.Fatalf("frame@0/A decisions = %+v, want none", f0.GetDecisions())
	}

	// seq 3: A#d1 requested (idx 1) and wa1 dispatched (idx 2) — pending with one chosen work.
	f3, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 3, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(3,A): %v", err)
	}
	if got := ids(f3); !eq(got, []string{"A#d1/pending"}) {
		t.Fatalf("frame@3/A decisions = %v, want [A#d1/pending]", got)
	}
	if d := f3.GetDecisions(); len(d) != 1 || len(d[0].GetDispatches()) != 1 || d[0].GetDispatches()[0].GetWorkId() != "wa1" {
		t.Fatalf("frame@3/A A#d1 = %+v, want one dispatch of wa1", f3.GetDecisions())
	}

	// total: both A decisions completed; A#d2 carries the completion rationale;
	// mission B's decision never appears.
	fEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,A): %v", err)
	}
	if got := ids(fEnd); !eq(got, []string{"A#d1/completed", "A#d2/completed"}) {
		t.Fatalf("frame@end/A decisions = %v, want [A#d1/completed A#d2/completed]", got)
	}
	for _, d := range fEnd.GetDecisions() {
		if d.GetMissionId() != "A" {
			t.Fatalf("frame@end/A decision %q has mission_id %q, want A", d.GetId(), d.GetMissionId())
		}
		if d.GetId() == "A#d2" {
			if d.GetOutcome() != string(brain.MissionCompleted) {
				t.Fatalf("A#d2 outcome = %q, want %q", d.GetOutcome(), brain.MissionCompleted)
			}
			if d.GetRationale() != "goal resolved" {
				t.Fatalf("A#d2 rationale = %q, want %q", d.GetRationale(), "goal resolved")
			}
		}
	}
}

// TestWorldService_GetFrameAt_LlmCalls: the rich frame (PRD #1059 M2, gibson#1075)
// surfaces a mission's LLM calls reconstructed as-of the folded tick. A call is
// mission-scoped by the mission-evidence edge — its MissionID — the same edge hosts
// and findings use. Each call appears at its own observation tick (the set folds in
// cumulatively), token/cost metadata rides along, and a call made under another
// mission never bleeds into a scoped frame.
func TestWorldService_GetFrameAt_LlmCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "goal A"})                                                           // A idx 0
	e.Submit(brain.WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "agent", Target: "recon"})                     // A idx 1
	e.Submit(brain.LlmCallObserved{CallID: "ca1", MissionID: "A", Model: "m", PromptTokens: 10, CompletionTokens: 5}) // A idx 2
	e.Submit(brain.LlmCallObserved{CallID: "cam", MissionID: "A", Model: "m", PromptTokens: 3, CompletionTokens: 1})  // A idx 3
	e.Submit(brain.WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "agent", Target: "recon"})                     // mission B
	e.Submit(brain.LlmCallObserved{CallID: "cb1", MissionID: "B", Model: "m", PromptTokens: 7, CompletionTokens: 2})  // mission B call
	e.Submit(brain.LlmCallObserved{CallID: "camb", MissionID: "", Model: "m", PromptTokens: 1, CompletionTokens: 1})  // tenant-ambient (no mission)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 7 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	calls := func(r *worldpb.GetFrameAtResponse) []string {
		var out []string
		for _, c := range r.GetLlmCalls() {
			out = append(out, c.GetCallId())
		}
		sort.Strings(out)
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// seq 0: nothing folded — no calls.
	f0, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 0, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(0,A): %v", err)
	}
	if len(f0.GetLlmCalls()) != 0 {
		t.Fatalf("frame@0/A calls = %+v, want none", f0.GetLlmCalls())
	}

	// seq 2 folds MissionStarted + wa1 dispatch — ca1 (idx 2) not folded yet.
	f2, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 2, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(2,A): %v", err)
	}
	if got := calls(f2); !eq(got, nil) {
		t.Fatalf("frame@2/A calls = %v, want none", got)
	}

	// seq 3 folds the run-linked call: ca1 appears at its tick.
	f3, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 3, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(3,A): %v", err)
	}
	if got := calls(f3); !eq(got, []string{"ca1"}) {
		t.Fatalf("frame@3/A calls = %v, want [ca1]", got)
	}

	// total: both A's calls present with token metadata; mission B's call never appears.
	fEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,A): %v", err)
	}
	if got := calls(fEnd); !eq(got, []string{"ca1", "cam"}) {
		t.Fatalf("frame@end/A calls = %v, want [ca1 cam]", got)
	}
	for _, c := range fEnd.GetLlmCalls() {
		if c.GetCallId() == "cb1" {
			t.Fatal("mission B LLM call bled into mission A frame")
		}
		if c.GetCallId() == "camb" {
			t.Fatal("tenant-ambient LLM call (no mission) bled into mission A frame")
		}
		if c.GetCallId() == "ca1" {
			if c.GetPromptTokens() != 10 || c.GetCompletionTokens() != 5 {
				t.Fatalf("ca1 tokens = %d/%d, want 10/5", c.GetPromptTokens(), c.GetCompletionTokens())
			}
		}
	}
}

// TestWorldService_GetFrameAt_HostsAndFindings: a mission-scoped frame surfaces the
// hosts and findings the mission's work discovered (the mission-evidence edge,
// gibson#1075) in the view the dashboard hosts/findings panels bind to, with no
// cross-mission or tenant-ambient bleed.
func TestWorldService_GetFrameAt_HostsAndFindings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "goal A"})
	e.Submit(brain.HostObserved{MissionID: "A", ScopeID: "sA", Address: "10.0.0.5", SSHHostKey: "AAAA"})
	e.Submit(brain.FindingRaised{ID: "f-a", Title: "A finding", ScopeID: "sA", Address: "10.0.0.5", Severity: "high", MissionID: "A"})
	e.Submit(brain.MissionStarted{ID: "B", Goal: "goal B"})
	e.Submit(brain.HostObserved{MissionID: "B", ScopeID: "sB", Address: "10.0.1.9", SSHHostKey: "CCCC"})
	e.Submit(brain.FindingRaised{ID: "f-b", Title: "B finding", ScopeID: "sB", Address: "10.0.1.9", Severity: "low", MissionID: "B"})
	e.Submit(brain.HostObserved{ScopeID: "sX", Address: "10.0.2.2", SSHHostKey: "DDDD"}) // tenant-ambient

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 7 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	a, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99, MissionId: "A"})
	if err != nil {
		t.Fatalf("GetFrameAt(99,A): %v", err)
	}
	addrs := map[string]bool{}
	for _, h := range a.GetHosts() {
		addrs[h.GetAddress()] = true
	}
	if !addrs["10.0.0.5"] {
		t.Fatalf("mission A frame missing its host; hosts=%v", addrs)
	}
	if addrs["10.0.1.9"] || addrs["10.0.2.2"] {
		t.Fatalf("foreign/ambient host bled into mission A frame; hosts=%v", addrs)
	}
	titles := map[string]bool{}
	for _, f := range a.GetFindings() {
		titles[f.GetTitle()] = true
	}
	if !titles["A finding"] {
		t.Fatalf("mission A frame missing its finding; findings=%v", titles)
	}
	if titles["B finding"] {
		t.Fatal("mission B finding bled into mission A frame")
	}
}
