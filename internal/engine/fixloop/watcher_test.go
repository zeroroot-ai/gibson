// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

var t0 = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

type fakeReader struct {
	mr     MergeFact
	deploy DeployFact
	health HealthFact
	err    error
}

func (f *fakeReader) MergeRequest(context.Context, string, string, string) (MergeFact, error) {
	return f.mr, f.err
}
func (f *fakeReader) Deploy(context.Context, string, string, string) (DeployFact, error) {
	return f.deploy, f.err
}
func (f *fakeReader) Health(context.Context, string, string, string, time.Time, time.Duration) (HealthFact, error) {
	return f.health, f.err
}

type fakeReverter struct {
	calls    []string
	missions []string
	err      error
	// waiting leaves the revert merge request open: its pipeline runs.
	waiting bool
}

func (r *fakeReverter) Revert(_ context.Context, _, mr, missionID string) (RevertFact, error) {
	r.calls = append(r.calls, mr)
	r.missions = append(r.missions, missionID)
	if r.err != nil {
		return RevertFact{}, r.err
	}
	return RevertFact{Merged: !r.waiting, RevertMergeRequest: "mr-1-revert"}, nil
}

type fakePlacer struct{ app string }

func (p fakePlacer) Application(context.Context, string, string) (string, error) { return p.app, nil }

// rig is one World, one fake host and one Watcher.
type rig struct {
	t   *testing.T
	w   *brain.World
	r   *fakeReader
	rv  *fakeReverter
	wt  *Watcher
	now time.Time
}

func newRig(t *testing.T, check string) *rig {
	t.Helper()
	rg := &rig{t: t, w: brain.NewWorld("t1"), r: &fakeReader{}, rv: &fakeReverter{}, now: at(5)}
	wt, err := NewWatcher(rg.r, rg.rv, fakePlacer{app: "app-1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rg.wt = wt
	rg.wt.now = func() time.Time { return rg.now }
	brain.Reduce(rg.w, brain.FindingRaised{ID: "f1", CheckKind: check, CheckRef: "ref", At: at(0)})
	// The fix job delivered a merge request.
	brain.Reduce(rg.w, brain.FindingStatusChanged{
		ID: "f1", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", MissionID: "fix-run-1", At: at(1),
	})
	return rg
}

// tick runs the Watcher, applies its events, and runs the Systems.
func (g *rig) tick() []brain.Event {
	evs := g.wt.Step(context.Background(), "t1", g.w.FindingSnapshot(), g.w.MergeSlots())
	for _, e := range evs {
		brain.Reduce(g.w, e)
	}
	for _, sys := range []brain.System{
		brain.MergeRequestReconciliationSystem, brain.MergeGateSystem, brain.VerificationSystem,
	} {
		for _, e := range sys(g.w) {
			brain.Reduce(g.w, e)
		}
	}
	return evs
}

func (g *rig) status() string {
	for _, f := range g.w.FindingSnapshot() {
		if f.ID == "f1" {
			return f.Status
		}
	}
	g.t.Fatal("finding f1 not found")
	return ""
}

func (g *rig) merged() {
	g.r.mr = MergeFact{State: MRMerged, At: at(2)}
	g.tick()
}

func (g *rig) deployed() {
	g.r.deploy = DeployFact{Deployed: true, DeploymentKey: "dep-1", ApplicationKey: "app-1", At: at(3)}
	g.tick()
}

// A merge request with a green pipeline asks for the slot of its Application.
func TestStep_GreenPipelineQueuesTheMergeRequest(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	if !g.w.MayMerge("mr-1", "fix-run-1") {
		t.Fatalf("slots = %+v, want a granted slot for mr-1", g.w.MergeSlots())
	}
}

// A red pipeline asks for no slot.
func TestStep_RedPipelineQueuesNothing(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: false}
	g.tick()
	if len(g.w.MergeSlots()) != 0 {
		t.Fatalf("slots = %+v, want none", g.w.MergeSlots())
	}
}

// A refusal is one Timeline event. The finding stays fixing.
func TestStep_RefusalIsOneEventAndTheFindingStaysFixing(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MRRefused, Reason: "review required", At: at(2)}
	first := g.tick()
	second := g.tick()
	if len(first) != 1 || len(second) != 0 {
		t.Fatalf("events = %d then %d, want 1 then 0", len(first), len(second))
	}
	if got := g.status(); got != brain.FindingStatusFixing {
		t.Fatalf("status = %q, want fixing", got)
	}
	// A new reason is a new event.
	g.r.mr.Reason = "checks required"
	if third := g.tick(); len(third) != 1 {
		t.Fatalf("a new reason gave %d events, want 1", len(third))
	}
}

// The merge, the deploy and a held signal, then a clean rerun, give verified.
func TestStep_FullLoopVerifies(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	if got := g.status(); got != brain.FindingStatusFixed {
		t.Fatalf("after merge: status = %q, want fixed", got)
	}
	g.deployed()
	g.r.health = HealthFact{Known: true, Done: true, Held: true, At: at(4)}
	g.tick()
	brain.Reduce(g.w, brain.CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	g.tick()
	if got := g.status(); got != brain.FindingStatusVerified {
		t.Fatalf("status = %q, want verified", got)
	}
}

// A connector that says done and held before the hold time ran gives no
// verdict. The daemon checks the time itself (review m3).
func TestStep_AHeldSignalMustCoverTheHoldTime(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	since := g.w.FindingSnapshot()[0].DeployedAt
	g.r.health = HealthFact{Known: true, Done: true, Held: true, At: since.Add(time.Minute)}
	for _, e := range g.tick() {
		if _, ok := e.(brain.HealthObserved); ok {
			t.Fatalf("a held signal one minute after the deploy gave %+v", e)
		}
	}
	g.r.health.At = since.Add(DefaultPolicy().HoldTime)
	var held bool
	for _, e := range g.tick() {
		if h, ok := e.(brain.HealthObserved); ok && h.Held {
			held = true
		}
	}
	if !held {
		t.Fatal("a held signal at the end of the hold time gave no verdict")
	}
}

// The deploy of a merged fix is a Timeline event with its time, and the graph
// gets the edge from the merge request to its Deployment (gibson#1460). A fix
// that is merged and not deployed gets neither.
func TestStep_TheDeployLinksTheMergeRequestToItsDeployment(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	if evs := g.tick(); len(evs) != 0 {
		t.Fatalf("merged and not deployed gave %+v", evs)
	}
	g.r.deploy = DeployFact{Deployed: true, DeploymentKey: "dep-1", ApplicationKey: "group/app", At: at(3)}
	evs := g.tick()
	var deploy *brain.DeployObserved
	var edge *brain.EntityEdge
	for _, e := range evs {
		switch ev := e.(type) {
		case brain.DeployObserved:
			deploy = &ev
		case brain.EntityObserved:
			if ev.Label == "MergeRequest" && ev.Key == "mr-1" && len(ev.Edges) == 1 {
				edge = &ev.Edges[0]
			}
		}
	}
	if deploy == nil || !deploy.At.Equal(at(3)) || deploy.MissionID != "fix-run-1" {
		t.Fatalf("deploy event = %+v", deploy)
	}
	if edge == nil || edge.Type != "DEPLOYED_IN" || edge.TargetLabel != "Deployment" || edge.TargetKey != "dep-1" {
		t.Fatalf("edge = %+v", edge)
	}
}

// A hold time that still runs gives no event.
func TestStep_HoldTimeStillRunningGivesNoHealthEvent(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.health = HealthFact{Known: true, Done: false}
	for _, e := range g.tick() {
		if _, ok := e.(brain.HealthObserved); ok {
			t.Fatalf("got %T while the hold time runs", e)
		}
	}
}

// A service with no health signal keeps its finding at fixed, even after a
// clean rerun.
func TestStep_NoHealthSignalKeepsTheFindingFixed(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.health = HealthFact{Known: false}
	g.tick()
	g.tick()
	for _, f := range g.w.FindingSnapshot() {
		if !f.HealthUnavailableAt.Equal(g.now) {
			t.Fatalf("HealthUnavailableAt = %v, want %v", f.HealthUnavailableAt, g.now)
		}
	}
	brain.Reduce(g.w, brain.CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	g.tick()
	if got := g.status(); got != brain.FindingStatusFixed {
		t.Fatalf("status = %q, want fixed", got)
	}
}

// A failed signal reverts the merge once, and the finding is open again.
func TestStep_FailedHealthRevertsAndReopens(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.health = HealthFact{Known: true, Done: true, Held: false, At: at(4)}
	g.tick() // records the failed signal
	g.tick() // reverts
	if got := g.status(); got != brain.FindingStatusOpen {
		t.Fatalf("status = %q, want open", got)
	}
	if len(g.rv.calls) != 1 || g.rv.calls[0] != "mr-1" {
		t.Fatalf("revert calls = %v, want [mr-1]", g.rv.calls)
	}
	g.tick()
	if len(g.rv.calls) != 1 {
		t.Fatalf("revert calls = %v after a second tick, want one", g.rv.calls)
	}
}

// A revert whose merge request waits for its pipeline leaves the finding
// fixed. FixReverted comes only after the host merged the revert, and each
// event carries the mission of the fix (gibson#1465).
func TestStep_ARevertThatWaitsKeepsTheFindingFixed(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.health = HealthFact{Known: true, Done: true, Held: false, At: at(4)}
	g.rv.waiting = true
	g.tick() // records the failed signal
	evs := g.tick()
	if len(evs) != 1 {
		t.Fatalf("events = %+v, want one RevertRequested", evs)
	}
	req, ok := evs[0].(brain.RevertRequested)
	if !ok || req.MissionID != "fix-run-1" || req.RevertMergeRequest != "mr-1-revert" {
		t.Fatalf("event = %+v", evs[0])
	}
	if got := g.status(); got != brain.FindingStatusFixed {
		t.Fatalf("status = %q, want fixed while the revert waits", got)
	}
	if evs := g.tick(); len(evs) != 0 {
		t.Fatalf("a second pass while the revert waits gave %+v", evs)
	}
	g.rv.waiting = false
	evs = g.tick()
	if len(evs) != 1 {
		t.Fatalf("events = %+v, want one FixReverted", evs)
	}
	if rev, ok := evs[0].(brain.FixReverted); !ok || rev.MissionID != "fix-run-1" {
		t.Fatalf("event = %+v", evs[0])
	}
	if got := g.status(); got != brain.FindingStatusOpen {
		t.Fatalf("status = %q, want open", got)
	}
	for _, m := range g.rv.missions {
		if m != "fix-run-1" {
			t.Fatalf("revert missions = %v", g.rv.missions)
		}
	}
}

// A revert that fails is tried again, and the finding stays fixed until it
// works.
func TestStep_FailedRevertIsRetried(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.health = HealthFact{Known: true, Done: true, Held: false, At: at(4)}
	g.rv.err = errors.New("host down")
	g.tick() // records the failed signal
	g.tick()
	g.tick()
	if len(g.rv.calls) != 2 || g.status() != brain.FindingStatusFixed {
		t.Fatalf("calls = %v, status = %q", g.rv.calls, g.status())
	}
	g.rv.err = nil
	g.tick()
	if got := g.status(); got != brain.FindingStatusOpen {
		t.Fatalf("status = %q, want open", got)
	}
}

// A restart that runs longer than the limit is a failed signal. A restart that
// ends in time moves the start of the hold time to its end.
func TestStep_RestartLimit(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.deploy.Restart = RestartFact{Needed: true, Started: at(3), Ended: at(3).Add(40 * time.Minute)}
	g.tick()
	g.tick()
	if got := g.status(); got != brain.FindingStatusOpen {
		t.Fatalf("a restart of 40 minutes: status = %q, want open", got)
	}

	h := newRig(t, "scan")
	h.merged()
	h.deployed()
	h.r.deploy.Restart = RestartFact{Needed: true, Started: at(3), Ended: at(3).Add(5 * time.Minute)}
	h.r.health = HealthFact{Known: true, Done: true, Held: true, At: at(4)}
	h.tick()
	if len(h.rv.calls) != 0 {
		t.Fatalf("a restart of 5 minutes reverted: %v", h.rv.calls)
	}
}

// A restart that still runs and is inside the limit gives no event.
func TestStep_RestartStillRunningWaits(t *testing.T) {
	g := newRig(t, "scan")
	g.merged()
	g.deployed()
	g.r.deploy.Restart = RestartFact{Needed: true, Started: g.now.Add(-time.Minute)}
	g.r.health = HealthFact{Known: true, Done: true, Held: true}
	for _, e := range g.tick() {
		if _, ok := e.(brain.HealthObserved); ok {
			t.Fatalf("got %T during the restart", e)
		}
	}
}

// A read that fails moves nothing.
func TestStep_ReadErrorMovesNothing(t *testing.T) {
	g := newRig(t, "scan")
	g.r.err = errors.New("connector down")
	if evs := g.tick(); len(evs) != 0 {
		t.Fatalf("events = %v", evs)
	}
	if got := g.status(); got != brain.FindingStatusFixing {
		t.Fatalf("status = %q", got)
	}
}

// An agent that reports a merge request as merged through the entity path
// changes no status. Only the read of the Git host moves a finding.
func TestAgentClaimMovesNoFinding(t *testing.T) {
	g := newRig(t, "scan")
	brain.Reduce(g.w, brain.EntityObserved{
		Label: "MergeRequest", Key: "mr-1",
		Props: map[string]string{"state": "merged", "health": "held", "deployed": "true"},
	})
	for _, sys := range []brain.System{
		brain.MergeRequestReconciliationSystem, brain.MergeGateSystem, brain.VerificationSystem,
	} {
		if evs := sys(g.w); len(evs) != 0 {
			t.Fatalf("%T events after an agent claim: %v", sys, evs)
		}
	}
	if got := g.status(); got != brain.FindingStatusFixing {
		t.Fatalf("status = %q, want fixing", got)
	}
}

// A watcher needs its reader, its reverter and its placer at construction.
func TestNewWatcher_RefusesAMissingDependency(t *testing.T) {
	r, rv := &fakeReader{}, &fakeReverter{}
	if _, err := NewWatcher(nil, rv, fakePlacer{}, nil, nil); err == nil {
		t.Error("no reader: want an error")
	}
	if _, err := NewWatcher(r, nil, fakePlacer{}, nil, nil); err == nil {
		t.Error("no reverter: want an error")
	}
	if _, err := NewWatcher(r, rv, nil, nil, nil); err == nil {
		t.Error("no placer: want an error")
	}
}

// A merge request whose findings name no fix mission gets no merge slot: no
// call could merge with it, and it would hold the Application (review, final).
func TestStep_NoSlotForAMergeRequestWithNoMission(t *testing.T) {
	w := brain.NewWorld("t1")
	brain.Reduce(w, brain.FindingRaised{ID: "f1", At: at(0)})
	brain.Reduce(w, brain.FindingStatusChanged{ID: "f1", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: at(1)})
	r := &fakeReader{mr: MergeFact{State: MROpen, PipelineGreen: true}}
	wt, err := NewWatcher(r, &fakeReverter{}, fakePlacer{app: "app-1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range wt.Step(context.Background(), "t1", w.FindingSnapshot(), w.MergeSlots()) {
		if _, ok := ev.(brain.MergeRequestQueued); ok {
			t.Fatalf("a merge request with no mission was queued: %+v", ev)
		}
	}
}

// agentWaits makes a run of an agent mission ask for the merge of mr-1, as the
// merge call of the agent does when the slot is not granted yet.
func (g *rig) agentWaits() {
	brain.Reduce(g.w, brain.MissionStarted{ID: "agent-1", RunID: "run-1"})
	brain.Reduce(g.w, brain.MergeAsked{MergeRequest: "mr-1", MissionID: "agent-1", RunID: "run-1", At: at(5)})
}

func (g *rig) agentRunEnds() {
	brain.Reduce(g.w, brain.MissionDone{ID: "agent-1", RunID: "run-1", Outcome: brain.MissionCompleted})
}

func hasEvent[T brain.Event](evs []brain.Event) bool {
	for _, e := range evs {
		if _, ok := e.(T); ok {
			return true
		}
	}
	return false
}

func (g *rig) granted(mr string) bool {
	for _, s := range g.w.MergeSlots() {
		if s.MergeRequest == mr {
			return s.Granted
		}
	}
	return false
}

func (g *rig) hasSlot(mr string) bool {
	for _, s := range g.w.MergeSlots() {
		if s.MergeRequest == mr {
			return true
		}
	}
	return false
}

// The run that waited for the slot ends, and the host shows the merge request
// merged. The slot is not freed early: the merge request keeps its slot until its
// health signal answers, and the next fix of the Application does not get it
// (gibson#1609).
func TestStep_ARunThatMergedAndEndedFreesNoSlotEarly(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	brain.Reduce(g.w, brain.MergeRequestQueued{MergeRequest: "mr-2", Application: "app-1", At: at(5), MissionID: "fix-run-2"})
	g.agentWaits()
	g.agentRunEnds()

	g.r.mr = MergeFact{State: MRMerged, At: at(6)}
	evs := g.tick()

	if hasEvent[brain.MergeSlotExpired](evs) {
		t.Fatalf("a slot was freed for a merge request that the host shows as merged: %+v", evs)
	}
	if !hasEvent[brain.MergeRequestObserved](evs) {
		t.Fatalf("events = %+v, want the merged state recorded", evs)
	}
	if !g.hasSlot("mr-1") {
		t.Fatal("the merged fix lost its slot before its health signal")
	}
	if g.granted("mr-2") {
		t.Fatal("a second fix of the Application was granted before the health verdict of the first")
	}
}

// The run ends and the host shows the merge request open. The slot leaves the
// queue, the other fix of the Application gets its slot after that, and the
// finding stays fixing with its merge request.
func TestStep_ARunThatEndedWithTheMergeRequestOpenFreesTheSlotForTheNextFix(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	brain.Reduce(g.w, brain.MergeRequestQueued{MergeRequest: "mr-2", Application: "app-1", At: at(5), MissionID: "fix-run-2"})
	g.agentWaits()
	if !g.granted("mr-1") || g.granted("mr-2") {
		t.Fatalf("slots = %+v, want mr-1 granted and mr-2 waiting", g.w.MergeSlots())
	}

	// The run still waits: nothing is freed.
	if evs := g.tick(); hasEvent[brain.MergeSlotExpired](evs) || g.granted("mr-2") {
		t.Fatalf("a live run lost its slot: %+v", evs)
	}

	g.agentRunEnds()
	evs := g.tick()
	if !hasEvent[brain.MergeSlotExpired](evs) {
		t.Fatalf("events = %+v, want the slot of mr-1 freed", evs)
	}
	if g.hasSlot("mr-1") {
		t.Fatal("the freed slot stayed in the queue")
	}
	if !g.granted("mr-2") {
		t.Fatalf("slots = %+v, want the other fix granted after the first slot is gone", g.w.MergeSlots())
	}
	if got := g.status(); got != brain.FindingStatusFixing {
		t.Fatalf("status = %q, want fixing with its open merge request", got)
	}
}

// A slot that the Watcher freed is asked for again only after the backoff, so a
// merge request that no agent merges does not churn the queue. After the backoff
// it is queued again, and the next merge call of the agent can be granted.
func TestStep_AFreedSlotIsQueuedAgainAfterTheBackoff(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.agentWaits()
	g.agentRunEnds()
	g.tick() // frees mr-1
	if g.hasSlot("mr-1") {
		t.Fatal("the slot was not freed")
	}

	g.now = g.now.Add(RequeueBackoff - time.Minute)
	for range 3 {
		g.tick()
	}
	if g.hasSlot("mr-1") {
		t.Fatal("the merge request was queued again inside the backoff")
	}

	g.now = g.now.Add(2 * time.Minute)
	g.tick()
	if !g.hasSlot("mr-1") {
		t.Fatal("the merge request was not queued again after the backoff")
	}
	if !g.granted("mr-1") {
		t.Fatal("the new slot was not granted, so the next merge call of the agent would be refused")
	}
}
