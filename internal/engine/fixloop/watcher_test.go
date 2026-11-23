// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
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
			// The World stamps a grant with its own clock. The rig puts the time of
			// the rig on it, so the grant window is a rig time.
			if mg, ok := e.(brain.MergeGranted); ok {
				mg.At = g.now
				e = mg
			}
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
	if !g.w.MayMerge("mr-1") {
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

// queueSecondFix puts a second fix of the same Application in the queue. It has
// no finding, so the Watcher reads only the first merge request.
func (g *rig) queueSecondFix() {
	brain.Reduce(g.w, brain.MergeRequestQueued{MergeRequest: "mr-2", Application: "app-1", At: g.now, MissionID: "fix-run-2"})
}

// A granted slot that no merge used is freed after the grant window, and the
// other fix of the Application gets its slot only after the first slot is gone.
// The finding stays fixing with its open merge request (gibson#1609).
func TestStep_AGrantedSlotThatNoMergeUsedIsQueuedAgainAfterTheWindow(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.tick()
	if !g.granted("mr-1") || g.granted("mr-2") {
		t.Fatalf("slots = %+v, want mr-1 granted and mr-2 waiting", g.w.MergeSlots())
	}

	// Inside the window nothing is freed.
	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow - time.Minute)
	if evs := g.tick(); hasEvent[brain.MergeSlotExpired](evs) || g.granted("mr-2") {
		t.Fatalf("a slot was freed inside the window: %+v", evs)
	}

	// After the window the host shows the merge request open. The slot leaves the
	// queue, and the next fix of the Application gets its slot after that.
	g.now = g.now.Add(2 * time.Minute)
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

// A granted slot whose merge request merged on the host is closed as merged. It
// is not freed and not queued again, and the second fix does not get the slot
// before the health verdict (gibson#1609).
func TestStep_AMergedMergeRequestIsNotFreedAfterTheWindow(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow + time.Hour)

	g.r.mr = MergeFact{State: MRMerged, At: g.now}
	evs := g.tick()

	if hasEvent[brain.MergeSlotExpired](evs) {
		t.Fatalf("a slot was freed for a merge request that the host shows as merged: %+v", evs)
	}
	if !hasEvent[brain.MergeRequestObserved](evs) {
		t.Fatalf("events = %+v, want the merged state recorded", evs)
	}
	if !g.hasSlot("mr-1") || g.granted("mr-2") {
		t.Fatalf("slots = %+v, want mr-1 kept and mr-2 waiting for the health verdict", g.w.MergeSlots())
	}
}

// A merge call inside the window merges, and the slot is not freed by the
// window afterwards: the merge request is merged on the host.
func TestStep_ALateMergeCallInsideTheWindowMerges(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow - time.Minute)
	if !g.w.MayMerge("mr-1") {
		t.Fatal("the granted slot refused the merge call inside the window")
	}
	g.tick()
	if !g.granted("mr-1") {
		t.Fatal("the slot was freed inside the window")
	}
}

// A freed slot is asked for again only after the backoff, so a merge request that
// no agent merges does not churn the queue. After the backoff it is queued again
// behind the others, and the next merge call of the agent can be granted.
func TestStep_AFreedSlotIsQueuedAgainAfterTheBackoff(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow + time.Minute)
	g.tick() // frees mr-1
	if g.hasSlot("mr-1") {
		t.Fatal("the slot was not freed")
	}

	g.now = g.now.Add(DefaultPolicy().RequeueBackoff - time.Minute)
	for range 3 {
		g.tick()
	}
	if g.hasSlot("mr-1") {
		t.Fatal("the merge request was queued again inside the backoff")
	}

	g.now = g.now.Add(2 * time.Minute)
	g.tick()
	if !g.hasSlot("mr-1") || !g.granted("mr-1") {
		t.Fatalf("slots = %+v, want the merge request queued again and granted", g.w.MergeSlots())
	}
}

// A policy that states no window takes the default, so a slot is never freed at
// the moment of its grant.
func TestStep_AZeroWindowTakesTheDefault(t *testing.T) {
	g := newRig(t, "scan")
	g.wt.policy = func(string) Policy { return Policy{HoldTime: time.Minute} }
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	if evs := g.tick(); hasEvent[brain.MergeSlotExpired](evs) {
		t.Fatalf("a slot was freed at the moment of its grant: %+v", evs)
	}
}

func eventsOf[T brain.Event](evs []brain.Event) []T {
	var out []T
	for _, e := range evs {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// B. The host refuses the merge and the merge request is still open. The slot
// stays, so no second fix of the Application ships while a person may merge the
// merge request by hand. The refusal and its reason are the wait on a person.
// The finding stays fixing.
func TestStep_ARefusedMergeKeepsTheSlotAndRecordsTheWait(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.tick()

	g.r.mr = MergeFact{State: MRRefused, Reason: "branch protection requires a review", PipelineGreen: true, At: g.now}
	evs := g.tick()
	obs := eventsOf[brain.MergeRequestObserved](evs)
	if len(obs) != 1 || obs[0].State != brain.MergeRequestRefused || obs[0].Reason != "branch protection requires a review" {
		t.Fatalf("observed = %+v, want one refusal with its reason", obs)
	}
	if hasEvent[brain.MergeSlotExpired](evs) || !g.granted("mr-1") || g.granted("mr-2") {
		t.Fatalf("a refused merge freed its slot: %+v", evs)
	}
	if got := g.status(); got != brain.FindingStatusFixing {
		t.Fatalf("status = %q, want fixing", got)
	}

	// The refusal is one event, and the slot stays, whatever the time.
	g.now = g.now.Add(10 * DefaultPolicy().MergeGrantWindow)
	for range 3 {
		if more := g.tick(); len(more) != 0 {
			t.Fatalf("a standing refusal gave events: %+v", more)
		}
	}
	if !g.granted("mr-1") || g.granted("mr-2") {
		t.Fatal("a clock moved the slot of a refused merge")
	}
}

// A person merges the refused merge request by hand. The host then shows it
// merged, and the normal path goes on: the slot stays for the health verdict.
func TestStep_ARefusedMergeThatAPersonMergedGoesTheNormalPath(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.r.mr = MergeFact{State: MRRefused, Reason: "review required", At: g.now}
	g.tick()
	g.r.mr = MergeFact{State: MRMerged, At: g.now}
	g.tick()
	if got := g.status(); got != brain.FindingStatusFixed {
		t.Fatalf("status = %q, want fixed", got)
	}
	if !g.hasSlot("mr-1") || g.granted("mr-2") {
		t.Fatal("a second fix was granted before the health verdict of the merged fix")
	}
}

// The host closes a refused merge request. The slot goes and the finding opens
// again, as for any closed merge request.
func TestStep_ARefusedMergeRequestThatTheHostClosedFreesItsSlot(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.r.mr = MergeFact{State: MRRefused, Reason: "review required", At: g.now}
	g.tick()
	g.r.mr = MergeFact{State: MRClosed, At: g.now}
	g.tick()
	if g.hasSlot("mr-1") || g.status() != brain.FindingStatusOpen {
		t.Fatalf("slots = %+v status = %q, want the slot gone and the finding open", g.w.MergeSlots(), g.status())
	}
}

// The refusal wait ends on the next read that is not refused.
func TestStep_ARefusalEndsWhenTheMergeRequestIsPlainOpenAgain(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.r.mr = MergeFact{State: MRRefused, Reason: "review required", At: g.now}
	g.tick()
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true, At: g.now}
	evs := g.tick()
	obs := eventsOf[brain.MergeRequestObserved](evs)
	if len(obs) != 1 || obs[0].State != brain.MergeRequestOpen {
		t.Fatalf("observed = %+v, want one report that ends the refusal", obs)
	}
	if more := g.tick(); len(eventsOf[brain.MergeRequestObserved](more)) != 0 {
		t.Fatalf("the end of the refusal was recorded twice: %+v", more)
	}
}

// C. The daemon cannot read the merge request. It fails closed: the slot stays,
// the wait is visible once, and a later read that works ends the wait and goes on.
func TestStep_AnUnreadableMergeRequestKeepsTheSlotAndWaitsOnAPerson(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow + time.Hour)

	g.r.err = errors.New("the host is down")
	first := g.tick()
	waits := eventsOf[brain.FixWaiting](first)
	if len(waits) != 1 || !waits[0].Waiting || waits[0].WaitKind != brain.WaitMergeUnreadable ||
		waits[0].Reason != "the daemon cannot read the merge request on the Git host" {
		t.Fatalf("waits = %+v, want one visible wait with the reason", waits)
	}
	if hasEvent[brain.MergeSlotExpired](first) || !g.hasSlot("mr-1") || g.granted("mr-2") {
		t.Fatal("the slot was freed or passed on although the daemon cannot read the merge request")
	}
	if second := g.tick(); len(eventsOf[brain.FixWaiting](second)) != 0 {
		t.Fatalf("the wait was recorded twice: %+v", second)
	}

	// The host answers again, and the merge request is open past the window.
	g.r.err = nil
	later := g.tick()
	ended := eventsOf[brain.FixWaiting](later)
	if len(ended) != 1 || ended[0].Waiting || ended[0].WaitKind != brain.WaitMergeUnreadable {
		t.Fatalf("waits = %+v, want the wait ended", ended)
	}
	if !hasEvent[brain.MergeSlotExpired](later) {
		t.Fatalf("events = %+v, want the normal release after a read that works", later)
	}
}

// D. A merged fix with no health verdict after the grant window waits on a
// person. No clock frees the slot: the hold time of the health signal is
// gibson#1463.
func TestStep_AMergedFixWithNoVerdictAfterTheWindowWaitsOnAPersonAndKeepsItsSlot(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.merged()
	if got := g.status(); got != brain.FindingStatusFixed {
		t.Fatalf("status = %q, want fixed", got)
	}
	if evs := g.tick(); len(eventsOf[brain.FixWaiting](evs)) != 0 {
		t.Fatalf("a wait inside the window: %+v", evs)
	}

	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow + time.Hour)
	first := g.tick()
	waits := eventsOf[brain.FixWaiting](first)
	if len(waits) != 1 || waits[0].WaitKind != brain.WaitNoHealthVerdict || waits[0].Reason != "no health verdict" || !waits[0].Waiting {
		t.Fatalf("waits = %+v, want one wait with no health verdict", waits)
	}
	if !g.hasSlot("mr-1") || g.granted("mr-2") {
		t.Fatal("the slot was freed with no verdict")
	}
	if second := g.tick(); len(eventsOf[brain.FixWaiting](second)) != 0 {
		t.Fatalf("the wait was recorded twice: %+v", second)
	}
	g.now = g.now.Add(1000 * time.Hour)
	g.tick()
	if !g.hasSlot("mr-1") || g.granted("mr-2") {
		t.Fatal("a clock freed the slot of a merged fix")
	}
}

// E. A merge call that the gate allowed a moment ago may still be on its way to
// the host. The watcher frees no slot within the call bound. After the bound it
// reads the host again and frees it.
func TestStep_ASlotWithAnAllowedCallInFlightIsNotFreedUntilAfterTheBound(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.now = g.now.Add(DefaultPolicy().MergeGrantWindow + time.Minute)
	brain.Reduce(g.w, brain.MergeCallAllowed{MergeRequest: "mr-1", At: g.now.Add(-30 * time.Second)})

	if evs := g.tick(); hasEvent[brain.MergeSlotExpired](evs) || !g.hasSlot("mr-1") {
		t.Fatalf("a slot with a call in flight was freed: %+v", evs)
	}
	g.now = g.now.Add(DefaultPolicy().MergeCallBound)
	if evs := g.tick(); !hasEvent[brain.MergeSlotExpired](evs) || g.hasSlot("mr-1") {
		t.Fatalf("the slot was not freed after the call bound: %+v", evs)
	}
}

// 4. The open waits are on the slot, which the World folds from the Timeline. A
// new Watcher, as after a restart, neither repeats a wait nor misses its end.
func TestStep_ARestartBetweenTheBeginAndTheEndOfAWaitEndsIt(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.r.err = errors.New("the host is down")
	if len(eventsOf[brain.FixWaiting](g.tick())) != 1 {
		t.Fatal("the wait did not begin")
	}

	// The daemon restarts. The new Watcher holds no memory of the wait.
	restarted, err := NewWatcher(g.r, g.rv, fakePlacer{app: "app-1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return g.now }
	g.wt = restarted

	if again := g.tick(); len(eventsOf[brain.FixWaiting](again)) != 0 {
		t.Fatalf("a restart repeated the wait: %+v", again)
	}
	g.r.err = nil
	ended := eventsOf[brain.FixWaiting](g.tick())
	if len(ended) != 1 || ended[0].Waiting {
		t.Fatalf("waits = %+v, want the wait ended after the restart", ended)
	}
	if slots := g.w.MergeSlots(); len(slots) != 1 || len(slots[0].Waits) != 0 {
		t.Fatalf("slots = %+v, want no open wait", slots)
	}
}

// 3. A failed health signal keeps the slot until the revert merges. The list of
// items that wait on a person says why: the revert is pending, or the revert call
// failed (review M2, gibson#1609).
func TestStep_AFailedHealthSignalWithAnUnmergedRevertIsAVisibleWait(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	g.queueSecondFix()
	g.merged()
	g.deployed()
	g.r.health = HealthFact{Known: true, Done: true, Held: false, At: at(4)}
	g.rv.waiting = true // the revert merge request waits for its pipeline
	g.tick()
	g.tick()

	slots := g.w.MergeSlots()
	if len(slots) == 0 || slots[0].MergeRequest != "mr-1" {
		t.Fatalf("slots = %+v, want the slot of mr-1 kept", slots)
	}
	if reason := slots[0].Waits[brain.WaitRevertPending]; reason == "" {
		t.Fatalf("waits = %+v, want a revert pending wait with its reason", slots[0].Waits)
	}
	if g.granted("mr-2") {
		t.Fatal("a second fix was granted while the revert is pending")
	}

	// The revert call fails.
	g.rv.err = errors.New("the host refused the revert")
	g.tick()
	slots = g.w.MergeSlots()
	if slots[0].Waits[brain.WaitRevertFailed] == "" || slots[0].Waits[brain.WaitRevertPending] != "" {
		t.Fatalf("waits = %+v, want only the revert failed wait", slots[0].Waits)
	}

	// The revert merges. The slot leaves and the next fix goes.
	g.rv.err = nil
	g.rv.waiting = false
	g.tick()
	g.tick()
	if g.hasSlot("mr-1") || !g.granted("mr-2") {
		t.Fatalf("slots = %+v, want mr-1 gone and mr-2 granted after the revert merged", g.w.MergeSlots())
	}
}

// holdReader records the hold time and the mission that the Watcher reads the
// health signal for.
type holdReader struct {
	*fakeReader
	hold    time.Duration
	mission string
}

func (h *holdReader) Health(_ context.Context, _, mission, _ string, _ time.Time, hold time.Duration) (HealthFact, error) {
	h.hold, h.mission = hold, mission
	return h.health, h.err
}

// holdRig builds a rig whose reader records the health read, with the hold source.
func holdRig(t *testing.T, src HoldSource) (*rig, *holdReader) {
	t.Helper()
	g := newRig(t, "scan")
	hr := &holdReader{fakeReader: g.r}
	wt, err := NewWatcher(hr, g.rv, fakePlacer{app: "app-1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wt.WithHoldSource(src)
	wt.now = func() time.Time { return g.now }
	g.wt = wt
	g.r.health = HealthFact{Known: true} // the signal exists and the hold time still runs
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick() // the green pipeline queues the merge request, so it has a merge slot
	g.queueSecondFix()
	g.merged()
	g.deployed()
	g.tick() // the health read follows the deploy
	return g, hr
}

// The Watcher asks the hold source for the fix mission and reads the health
// signal with the hold time of that mission.
func TestStep_ReadsTheHoldTimeOfTheFixMission(t *testing.T) {
	var asked []string
	_, hr := holdRig(t, func(_ context.Context, tenant, missionID string) (time.Duration, error) {
		asked = append(asked, tenant+"/"+missionID)
		return 45 * time.Minute, nil
	})
	if hr.hold != 45*time.Minute {
		t.Errorf("the health signal was read with hold %v, want 45m", hr.hold)
	}
	if len(asked) == 0 || asked[0] != "t1/fix-run-1" {
		t.Errorf("the hold was asked for %v, want the fix mission of tenant t1", asked)
	}
}

// A mission that states no hold time gets the default hold time.
func TestStep_AMissionWithNoHoldGetsTheDefaultHold(t *testing.T) {
	_, hr := holdRig(t, func(context.Context, string, string) (time.Duration, error) { return 0, nil })
	if hr.hold != DefaultPolicy().HoldTime {
		t.Errorf("hold = %v, want the default %v", hr.hold, DefaultPolicy().HoldTime)
	}
}

// The hold is read once, at the deploy. A later read of the health signal uses the
// hold that the deploy event holds, so a deleted mission record never blocks it.
func TestStep_TheHoldIsReadOnceAtTheDeploy(t *testing.T) {
	calls := 0
	g, hr := holdRig(t, func(context.Context, string, string) (time.Duration, error) {
		calls++
		if calls > 1 {
			return 0, errors.New("the mission record is deleted")
		}
		return 45 * time.Minute, nil
	})
	g.tick()
	g.tick()
	if calls != 1 {
		t.Errorf("the hold source was asked %d times, want once", calls)
	}
	if hr.hold != 45*time.Minute {
		t.Errorf("hold = %v, want the 45m of the deploy event", hr.hold)
	}
}

// A fix mission record that is gone gives the upper bound of the hold, never the
// shorter default, and a visible wait with its own reason. The health signal is
// still read.
func TestStep_AGoneMissionRecordGivesTheUpperBoundAndAVisibleWait(t *testing.T) {
	g, hr := holdRig(t, func(context.Context, string, string) (time.Duration, error) {
		return 0, fmt.Errorf("read mission: %w", ErrHoldNotFound)
	})
	if hr.hold != MaxHold || hr.hold <= DefaultPolicy().HoldTime {
		t.Errorf("hold = %v, want the upper bound %v and not the default", hr.hold, MaxHold)
	}
	var reason string
	for _, sl := range g.w.MergeSlots() {
		if sl.MergeRequest == "mr-1" {
			reason = sl.Waits[brain.WaitHoldUnreadable]
		}
	}
	if reason != "the hold of the fix mission cannot be read" {
		t.Errorf("wait reason = %q, want its own reason (slots %+v)", reason, g.w.MergeSlots())
	}
	for _, sl := range g.w.MergeSlots() {
		if _, general := sl.Waits[brain.WaitNoHealthVerdict]; general {
			t.Error("the wait must not be the general no health verdict wait")
		}
	}
}

func TestHoldOf(t *testing.T) {
	if got := HoldOf(nil); got != 0 {
		t.Errorf("nil constraints = %v, want zero", got)
	}
	if got := HoldOf(&missionv1.MissionConstraints{HealthHold: durationpb.New(time.Hour)}); got != time.Hour {
		t.Errorf("hold = %v, want 1h", got)
	}
	if got := HoldOf(&missionv1.MissionConstraints{HealthHold: durationpb.New(0)}); got != 0 {
		t.Errorf("a zero hold = %v, want zero", got)
	}
}

// An error other than not found records no deploy in this pass, and the next step
// reads again. A transient error never shortens the hold.
func TestStep_ATransientHoldErrorRecordsNoDeployAndTheNextStepReadsAgain(t *testing.T) {
	fail := true
	g, hr := holdRig(t, func(context.Context, string, string) (time.Duration, error) {
		if fail {
			return 0, errors.New("the data plane is down")
		}
		return 45 * time.Minute, nil
	})
	if fs := g.w.FindingSnapshot(); !fs[0].DeployedAt.IsZero() {
		t.Fatalf("the deploy was recorded at %v while the hold could not be read", fs[0].DeployedAt)
	}
	if hr.mission != "" {
		t.Error("the health signal was read with no hold")
	}
	for _, sl := range g.w.MergeSlots() {
		if _, w := sl.Waits[brain.WaitHoldUnreadable]; w {
			t.Error("a transient error must not open the hold_unreadable wait")
		}
	}

	fail = false
	g.tick() // records the deploy with the hold
	g.tick() // reads the health signal
	if hr.hold != 45*time.Minute {
		t.Errorf("hold = %v, want the 45m that the next step read", hr.hold)
	}
}

func TestMaxHoldIsTheProtoBound(t *testing.T) {
	if MaxHold != 24*time.Hour {
		t.Errorf("MaxHold = %v, want 24h, the upper bound of health_hold", MaxHold)

// A fix that has no head, with the reason recorded, gets no merge slot. The fix
// agent makes no merge call without a head, so a slot would block the Application
// for the grant window at each cycle.
func TestStep_AFixWithNoHeadAndAReasonGetsNoMergeSlot(t *testing.T) {
	g := newRig(t, "scan")
	brain.Reduce(g.w, brain.FixHeadMissing{ID: "f1", MergeRequest: "mr-1", Reason: "the head moved", At: at(2)})
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}

	g.tick()

	if len(g.w.MergeSlots()) != 0 {
		t.Fatalf("slots = %+v, want none for a fix with no head", g.w.MergeSlots())
	}
}

// A fix with a head, and a fix whose head is not known yet, still get a slot.
func TestStep_AFixWithAHeadOrWithNoReasonGetsAMergeSlot(t *testing.T) {
	g := newRig(t, "scan")
	g.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	g.tick()
	if len(g.w.MergeSlots()) != 1 {
		t.Fatalf("slots = %+v, want one: the head is not known yet and no reason is recorded", g.w.MergeSlots())
	}

	h := newRig(t, "scan")
	brain.Reduce(h.w, brain.FixHeadRecorded{ID: "f1", MergeRequest: "mr-1", HeadSHA: "aaaa", At: at(2)})
	h.r.mr = MergeFact{State: MROpen, PipelineGreen: true}
	h.tick()
	if len(h.w.MergeSlots()) != 1 {
		t.Fatalf("slots = %+v, want one for a fix with a head", h.w.MergeSlots())
	}
}
