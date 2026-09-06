// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	bankstore "github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeStore is an in-memory bank.Store with only the parts the reconciler uses.
// The rest answer "not implemented", so a reconciler that started using one
// would fail loudly rather than silently.
type fakeStore struct {
	banks      []*bankstore.Bank
	members    map[string][]*bankstore.Member
	addErr     error
	removed    []string
	stateSet   []string
	listErr    error
	membersErr error
	stateErr   error
	removeErr  error
}

func newFakeStore(banks ...*bankstore.Bank) *fakeStore {
	return &fakeStore{banks: banks, members: map[string][]*bankstore.Member{}}
}

func (f *fakeStore) ListAll(context.Context, string) ([]*bankstore.Bank, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.banks, nil
}

func (f *fakeStore) ListMembers(_ context.Context, _, bankID string, _ bankstore.Page) ([]*bankstore.Member, string, error) {
	if f.membersErr != nil {
		return nil, "", f.membersErr
	}
	return f.members[bankID], "", nil
}

func (f *fakeStore) AddMember(_ context.Context, _ string, m *bankstore.Member) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.members[m.BankID] = append(f.members[m.BankID], m)
	return nil
}

func (f *fakeStore) SetMemberState(_ context.Context, _, memberID string, state bankstore.MemberState) (*bankstore.Member, error) {
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	f.stateSet = append(f.stateSet, memberID+"="+string(state))
	for _, ms := range f.members {
		for _, m := range ms {
			if m.ID == memberID {
				m.State = state
				return m, nil
			}
		}
	}
	return nil, bankstore.ErrNotFound
}

func (f *fakeStore) RemoveMember(_ context.Context, _, memberID string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, memberID)
	for bankID, ms := range f.members {
		kept := ms[:0]
		for _, m := range ms {
			if m.ID != memberID {
				kept = append(kept, m)
			}
		}
		f.members[bankID] = kept
	}
	return nil
}

func (f *fakeStore) Create(context.Context, string, bankstore.CreateInput) (*bankstore.Bank, error) {
	return nil, errors.New("not used by the reconciler")
}
func (f *fakeStore) Get(context.Context, string, string) (*bankstore.Bank, error) {
	return nil, errors.New("not used by the reconciler")
}
func (f *fakeStore) List(context.Context, string, bankstore.Page) ([]*bankstore.Bank, string, error) {
	return nil, "", errors.New("not used by the reconciler")
}
func (f *fakeStore) Update(context.Context, string, string, bankstore.UpdateInput) (*bankstore.Bank, error) {
	return nil, errors.New("not used by the reconciler")
}
func (f *fakeStore) Delete(context.Context, string, string) error {
	return errors.New("not used by the reconciler")
}
func (f *fakeStore) UpdateMemberStatus(context.Context, string, string, bankstore.MemberStatus) (*bankstore.Member, error) {
	return nil, errors.New("not used by the reconciler")
}

// fakeLauncher records what the reconciler asked for.
type fakeLauncher struct {
	launched  []string
	stopped   []string
	launchErr error
	stopErr   error
}

func (f *fakeLauncher) LaunchMember(_ context.Context, _ string, _ *bankstore.Bank, memberID string) (LaunchedMember, error) {
	if f.launchErr != nil {
		return LaunchedMember{}, f.launchErr
	}
	f.launched = append(f.launched, memberID)
	return LaunchedMember{
		MissionID: "mission-" + memberID, MissionRunID: "run-" + memberID,
		AgentRunID: "agent-" + memberID, SandboxID: "sbx-" + memberID,
	}, nil
}

func (f *fakeLauncher) StopMember(_ context.Context, _ string, m *bankstore.Member) error {
	f.stopped = append(f.stopped, m.ID)
	return f.stopErr
}

// recordingEvents captures what a console would have seen.
type recordingEvents struct{ launched, dead, draining, removed []string }

func (e *recordingEvents) MemberLaunched(_ context.Context, _ string, m *bankstore.Member) {
	e.launched = append(e.launched, m.ID)
}
func (e *recordingEvents) MemberDead(_ context.Context, _ string, m *bankstore.Member) {
	e.dead = append(e.dead, m.ID)
}
func (e *recordingEvents) MemberDraining(_ context.Context, _ string, m *bankstore.Member) {
	e.draining = append(e.draining, m.ID)
}
func (e *recordingEvents) MemberRemoved(_ context.Context, _ string, m *bankstore.Member) {
	e.removed = append(e.removed, m.ID)
}

var testNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func testBank(desired int32) *bankstore.Bank {
	return &bankstore.Bank{
		ID: "bank-1", Name: "nightly", OwnerKind: bankstore.OwnerUser, OwnerID: "alice",
		DesiredCount: desired, LoginShape: bankstore.LoginShapeAPIKey,
		ProviderConfigName: "p", AgentName: "claude", MaxJobsInFlight: 1,
	}
}

// fakeJobs records which members had their jobs released.
type fakeJobs struct {
	released []string
	err      error
}

func (f *fakeJobs) ReleaseMember(_ context.Context, _, memberID string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.released = append(f.released, memberID)
	return 1, nil
}

func newReconciler(t *testing.T, store bankstore.Store, l MemberLauncher, e Events) *Reconciler {
	t.Helper()
	return newReconcilerWithJobs(t, store, l, &fakeJobs{}, e)
}

func newReconcilerWithJobs(t *testing.T, store bankstore.Store, l MemberLauncher, jobs JobReleaser, e Events) *Reconciler {
	t.Helper()
	r, err := New(Config{Store: store, Launcher: l, Jobs: jobs, Events: e, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// liveMember is a member that reported a moment ago.
func liveMember(id string, state bankstore.MemberState, inFlight int32) *bankstore.Member {
	return &bankstore.Member{
		ID: id, BankID: "bank-1", State: state, JobsInFlight: inFlight, JobCap: 1,
		LastHeartbeat: testNow.Add(-time.Second), CreatedAt: testNow.Add(-time.Hour),
	}
}

func TestNew_RequiresAStoreAndALauncher(t *testing.T) {
	if _, err := New(Config{Store: newFakeStore(), Launcher: &fakeLauncher{}}); err == nil {
		t.Error("a reconciler with no job releaser must be refused: a dead member's jobs would hang forever")
	}
	if _, err := New(Config{Launcher: &fakeLauncher{}, Jobs: &fakeJobs{}}); err == nil {
		t.Error("a reconciler with no store must not be constructible")
	}
	if _, err := New(Config{Store: newFakeStore(), Jobs: &fakeJobs{}}); err == nil {
		t.Error("a reconciler with no launcher must not be constructible")
	}
}

// TestReconcileBank_LaunchesToTheDesiredCount: zero to N launches N.
func TestReconcileBank_LaunchesToTheDesiredCount(t *testing.T) {
	store, launcher, events := newFakeStore(), &fakeLauncher{}, &recordingEvents{}
	r := newReconciler(t, store, launcher, events)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(3)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(launcher.launched) != 3 {
		t.Fatalf("launched %d, want 3", len(launcher.launched))
	}
	if len(store.members["bank-1"]) != 3 {
		t.Fatalf("recorded %d members, want 3", len(store.members["bank-1"]))
	}
	if len(events.launched) != 3 {
		t.Errorf("events = %v, want one per launch", events.launched)
	}
	for _, m := range store.members["bank-1"] {
		if m.State != bankstore.MemberLaunching {
			t.Errorf("member %s starts in %q, want launching", m.ID, m.State)
		}
		if m.JobCap != 1 {
			t.Errorf("member %s cap = %d, want the bank's", m.ID, m.JobCap)
		}
		if m.SandboxID != "sbx-"+m.ID {
			t.Errorf("member %s carries no sandbox", m.ID)
		}
	}
}

// TestReconcileBank_SubscriptionMembersWaitForTheirOwner: the platform never
// holds the token, so a member cannot take work until its owner signs in.
func TestReconcileBank_SubscriptionMembersWaitForTheirOwner(t *testing.T) {
	store, launcher := newFakeStore(), &fakeLauncher{}
	r := newReconciler(t, store, launcher, nil)
	b := testBank(1)
	b.LoginShape = bankstore.LoginShapeSubscription
	b.ProviderConfigName = ""

	if err := r.ReconcileBank(context.Background(), "acme", b); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if got := store.members["bank-1"][0].State; got != bankstore.MemberNeedsSignIn {
		t.Fatalf("state = %q, want needs_sign_in", got)
	}
}

// TestReconcileBank_AtTheDesiredCountDoesNothing: a bank at its count neither
// launches nor drains.
func TestReconcileBank_AtTheDesiredCountDoesNothing(t *testing.T) {
	store, launcher := newFakeStore(), &fakeLauncher{}
	store.members["bank-1"] = []*bankstore.Member{
		liveMember("m-1", bankstore.MemberIdle, 0),
		liveMember("m-2", bankstore.MemberBusy, 1),
	}
	r := newReconciler(t, store, launcher, nil)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(2)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(launcher.launched) != 0 || len(launcher.stopped) != 0 || len(store.removed) != 0 {
		t.Fatalf("a bank at its desired count must be left alone: launched=%v stopped=%v removed=%v",
			launcher.launched, launcher.stopped, store.removed)
	}
}

// TestReconcileBank_ReplacesADeadMember: a member that stopped reporting does
// not count toward the desired total, or a bank of five with two dead members
// would sit at three forever.
func TestReconcileBank_ReplacesADeadMember(t *testing.T) {
	store, launcher, events := newFakeStore(), &fakeLauncher{}, &recordingEvents{}
	dead := liveMember("m-dead", bankstore.MemberIdle, 0)
	dead.LastHeartbeat = testNow.Add(-5 * time.Minute)
	store.members["bank-1"] = []*bankstore.Member{liveMember("m-1", bankstore.MemberIdle, 0), dead}
	r := newReconciler(t, store, launcher, events)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(2)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(events.dead) != 1 || events.dead[0] != "m-dead" {
		t.Fatalf("dead events = %v, want the silent member", events.dead)
	}
	if len(store.removed) != 1 || store.removed[0] != "m-dead" {
		t.Fatalf("removed = %v, want the dead member's row", store.removed)
	}
	if len(launcher.stopped) != 1 || launcher.stopped[0] != "m-dead" {
		t.Fatalf("stopped = %v; a sandbox that stopped answering is still killed", launcher.stopped)
	}
	if len(launcher.launched) != 1 {
		t.Fatalf("launched %d, want one replacement", len(launcher.launched))
	}
}

// TestReconcileBank_AMemberThatNeverReportedIsJudgedFromItsBirth: a launch that
// never came up is found rather than waited on forever.
func TestReconcileBank_AMemberThatNeverReportedIsJudgedFromItsBirth(t *testing.T) {
	store, launcher := newFakeStore(), &fakeLauncher{}
	stillborn := &bankstore.Member{
		ID: "m-stillborn", BankID: "bank-1", State: bankstore.MemberLaunching,
		CreatedAt: testNow.Add(-10 * time.Minute),
	}
	fresh := &bankstore.Member{
		ID: "m-fresh", BankID: "bank-1", State: bankstore.MemberLaunching,
		CreatedAt: testNow.Add(-2 * time.Second),
	}
	store.members["bank-1"] = []*bankstore.Member{stillborn, fresh}
	r := newReconciler(t, store, launcher, nil)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(2)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(store.removed) != 1 || store.removed[0] != "m-stillborn" {
		t.Fatalf("removed = %v, want only the member that never came up", store.removed)
	}
	if len(launcher.launched) != 1 {
		t.Fatalf("launched %d, want one replacement for the stillborn member", len(launcher.launched))
	}
}

// TestReconcileBank_DrainsIdleMembersFirst: draining a member that is nearly
// finished throws away more work than draining one doing nothing.
func TestReconcileBank_DrainsIdleMembersFirst(t *testing.T) {
	store, launcher, events := newFakeStore(), &fakeLauncher{}, &recordingEvents{}
	busy := liveMember("m-busy", bankstore.MemberBusy, 1)
	idle := liveMember("m-idle", bankstore.MemberIdle, 0)
	store.members["bank-1"] = []*bankstore.Member{busy, idle}
	r := newReconciler(t, store, launcher, events)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(1)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(events.draining) != 1 || events.draining[0] != "m-idle" {
		t.Fatalf("draining = %v, want the idle member", events.draining)
	}
	// An idle member has nothing to finish, so it goes at once rather than
	// leaving the bank above its desired count until the next pass.
	if len(store.removed) != 1 || store.removed[0] != "m-idle" {
		t.Fatalf("removed = %v, want the drained member gone in the same pass", store.removed)
	}
	if len(launcher.stopped) != 1 || launcher.stopped[0] != "m-idle" {
		t.Fatalf("stopped = %v", launcher.stopped)
	}
}

// TestReconcileBank_ABusyDrainingMemberKeepsWorking: a member asked to drain
// finishes its jobs before its sandbox is stopped.
func TestReconcileBank_ABusyDrainingMemberKeepsWorking(t *testing.T) {
	store, launcher := newFakeStore(), &fakeLauncher{}
	draining := liveMember("m-draining", bankstore.MemberDraining, 1)
	store.members["bank-1"] = []*bankstore.Member{draining, liveMember("m-1", bankstore.MemberIdle, 0)}
	r := newReconciler(t, store, launcher, nil)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(1)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(launcher.stopped) != 0 || len(store.removed) != 0 {
		t.Fatalf("a draining member with work in flight is left alone: stopped=%v removed=%v",
			launcher.stopped, store.removed)
	}
	if len(launcher.launched) != 0 {
		t.Fatalf("a draining member still holds its slot, so nothing is launched: %v", launcher.launched)
	}
}

// TestReconcileBank_ADrainedMemberIsRemoved: a draining member with nothing
// in flight is stopped and its row goes.
func TestReconcileBank_ADrainedMemberIsRemoved(t *testing.T) {
	store, launcher, events := newFakeStore(), &fakeLauncher{}, &recordingEvents{}
	store.members["bank-1"] = []*bankstore.Member{liveMember("m-drained", bankstore.MemberDraining, 0)}
	r := newReconciler(t, store, launcher, events)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(0)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(store.removed) != 1 || len(launcher.stopped) != 1 {
		t.Fatalf("removed=%v stopped=%v, want the drained member gone", store.removed, launcher.stopped)
	}
	if len(events.removed) != 1 {
		t.Errorf("removal events = %v", events.removed)
	}
}

// TestReconcileBank_StopsASandboxItCannotRecord: a sandbox with no row naming
// it is one nothing would ever reach or reap.
func TestReconcileBank_StopsASandboxItCannotRecord(t *testing.T) {
	store, launcher := newFakeStore(), &fakeLauncher{}
	store.addErr = errors.New("postgres down")
	r := newReconciler(t, store, launcher, nil)

	err := r.ReconcileBank(context.Background(), "acme", testBank(1))
	if err == nil {
		t.Fatal("a launch that could not be recorded must be reported")
	}
	if len(launcher.stopped) != 1 {
		t.Fatalf("stopped = %v, want the unrecordable sandbox stopped rather than leaked", launcher.stopped)
	}
}

// TestReconcileBank_ALaunchFailureDoesNotStopTheRest: every launch is tried
// and every failure is reported.
func TestReconcileBank_ALaunchFailureDoesNotStopTheRest(t *testing.T) {
	store, launcher := newFakeStore(), &fakeLauncher{launchErr: errors.New("no capacity")}
	r := newReconciler(t, store, launcher, nil)

	err := r.ReconcileBank(context.Background(), "acme", testBank(2))
	if err == nil || !strings.Contains(err.Error(), "no capacity") {
		t.Fatalf("err = %v, want both launch failures reported", err)
	}
}

// TestReconcileTenant_OneBadBankDoesNotFreezeTheTenant: the other banks are
// reconciled and the bad one is named.
func TestReconcileTenant_OneBadBankDoesNotFreezeTheTenant(t *testing.T) {
	good := testBank(1)
	bad := testBank(1)
	bad.ID = "bank-2"
	store := newFakeStore(bad, good)
	launcher := &countingLauncher{failFor: "bank-2"}
	r := newReconciler(t, store, launcher, nil)

	err := r.ReconcileTenant(context.Background(), "acme")
	if err == nil {
		t.Fatal("the failure must be reported")
	}
	if launcher.ok != 1 {
		t.Fatalf("the healthy bank still reconciled: launches = %d", launcher.ok)
	}
}

// countingLauncher fails for one bank and succeeds for the rest.
type countingLauncher struct {
	failFor string
	ok      int
}

func (c *countingLauncher) LaunchMember(_ context.Context, _ string, b *bankstore.Bank, memberID string) (LaunchedMember, error) {
	if b.ID == c.failFor {
		return LaunchedMember{}, errors.New("this bank is broken")
	}
	c.ok++
	return LaunchedMember{SandboxID: "sbx-" + memberID}, nil
}
func (c *countingLauncher) StopMember(context.Context, string, *bankstore.Member) error { return nil }

func TestReconcileTenant_ListFailureIsReported(t *testing.T) {
	store := newFakeStore()
	store.listErr = errors.New("postgres down")
	r := newReconciler(t, store, &fakeLauncher{}, nil)
	if err := r.ReconcileTenant(context.Background(), "acme"); err == nil {
		t.Fatal("a reconciler that cannot read the banks must say so")
	}
}

func TestDrainOrder(t *testing.T) {
	old := liveMember("old", bankstore.MemberIdle, 0)
	old.CreatedAt = testNow.Add(-2 * time.Hour)
	young := liveMember("young", bankstore.MemberIdle, 0)
	busy := liveMember("busy", bankstore.MemberBusy, 2)

	got := drainOrder([]*bankstore.Member{busy, young, old})
	if got[0].ID != "old" || got[1].ID != "young" || got[2].ID != "busy" {
		t.Fatalf("order = %s,%s,%s; want the idle oldest first and the busiest last",
			got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestNewMemberID_IsUnique(t *testing.T) {
	first, second := newMemberID(), newMemberID()
	if first == second {
		t.Fatal("two members must not share an id")
	}
}

func (f *fakeStore) MemberByRun(_ context.Context, _, runID string) (*bankstore.Member, error) {
	for _, ms := range f.members {
		for _, m := range ms {
			if m.MissionRunID == runID {
				return m, nil
			}
		}
	}
	return nil, bankstore.ErrNotFound
}

// TestReconcileBank_ADeadMembersJobsGoBackToTheQueue: the jobs a dead member
// held are released before its row goes, and a release failure keeps the row
// so the next pass tries again rather than orphans the jobs.
func TestReconcileBank_ADeadMembersJobsGoBackToTheQueue(t *testing.T) {
	store, launcher, jobs := newFakeStore(), &fakeLauncher{}, &fakeJobs{}
	dead := liveMember("m-dead", bankstore.MemberBusy, 1)
	dead.LastHeartbeat = testNow.Add(-5 * time.Minute)
	store.members["bank-1"] = []*bankstore.Member{dead}
	r := newReconcilerWithJobs(t, store, launcher, jobs, nil)

	if err := r.ReconcileBank(context.Background(), "acme", testBank(1)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if len(jobs.released) != 1 || jobs.released[0] != "m-dead" {
		t.Fatalf("released = %v, want the dead member's jobs", jobs.released)
	}
	if len(store.removed) != 1 {
		t.Fatalf("removed = %v, want the dead member's row", store.removed)
	}

	store, launcher = newFakeStore(), &fakeLauncher{}
	dead = liveMember("m-dead", bankstore.MemberBusy, 1)
	dead.LastHeartbeat = testNow.Add(-5 * time.Minute)
	store.members["bank-1"] = []*bankstore.Member{dead}
	r = newReconcilerWithJobs(t, store, launcher, &fakeJobs{err: errors.New("postgres is down")}, nil)
	if err := r.ReconcileBank(context.Background(), "acme", testBank(1)); err == nil {
		t.Fatal("a release failure must be reported")
	}
	if len(store.removed) != 0 {
		t.Fatal("a member whose jobs could not be released must keep its row")
	}
}

// TestRunner_PassesEveryTenantAndIsolatesFailures: one tenant's failure does
// not stop the others, and a tenant enumeration failure skips the pass.
func TestRunner_PassesEveryTenantAndIsolatesFailures(t *testing.T) {
	store := newFakeStore(testBank(1))
	launcher := &fakeLauncher{}
	r := newReconciler(t, store, launcher, nil)
	src := &fakeTenants{ids: []string{"acme", "globex"}}
	runner, err := NewRunner(RunnerConfig{Reconciler: r, Tenants: src, Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runner.Pass(context.Background())
	if len(launcher.launched) != 2 {
		t.Fatalf("launched %d, want one member per tenant", len(launcher.launched))
	}

	src.err = errors.New("kube is down")
	runner.Pass(context.Background())
	if len(launcher.launched) != 2 {
		t.Fatal("an enumeration failure must skip the pass")
	}

	if _, err := NewRunner(RunnerConfig{Tenants: src}); err == nil {
		t.Error("a runner needs a reconciler")
	}
	if _, err := NewRunner(RunnerConfig{Reconciler: r}); err == nil {
		t.Error("a runner needs a tenant source")
	}
}

// TestRunner_RunStopsWithItsContext asserts Run returns once ctx ends.
func TestRunner_RunStopsWithItsContext(t *testing.T) {
	r := newReconciler(t, newFakeStore(), &fakeLauncher{}, nil)
	runner, err := NewRunner(RunnerConfig{Reconciler: r, Tenants: &fakeTenants{}, Interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

type fakeTenants struct {
	ids []string
	err error
}

func (f *fakeTenants) ListTenants(context.Context) ([]auth.TenantID, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]auth.TenantID, 0, len(f.ids))
	for _, id := range f.ids {
		tid, err := auth.NewTenantID(id)
		if err != nil {
			return nil, fmt.Errorf("fake tenants: %w", err)
		}
		out = append(out, tid)
	}
	return out, nil
}

// TestReconcileBank_EveryStoreFailureIsReported: a failure on any store or
// launcher call reaches the caller, and a dead member's sandbox that cannot be
// stopped does not block its replacement.
func TestReconcileBank_EveryStoreFailureIsReported(t *testing.T) {
	deadMember := func() *bankstore.Member {
		m := liveMember("m-dead", bankstore.MemberIdle, 0)
		m.LastHeartbeat = testNow.Add(-5 * time.Minute)
		return m
	}
	ctx := context.Background()

	t.Run("list members", func(t *testing.T) {
		store := newFakeStore()
		store.membersErr = errors.New("postgres is down")
		r := newReconciler(t, store, &fakeLauncher{}, nil)
		if err := r.ReconcileBank(ctx, "acme", testBank(1)); err == nil {
			t.Fatal("a list failure must be reported")
		}
	})
	t.Run("mark dead", func(t *testing.T) {
		store := newFakeStore()
		store.members["bank-1"] = []*bankstore.Member{deadMember()}
		store.stateErr = errors.New("postgres is down")
		r := newReconciler(t, store, &fakeLauncher{}, nil)
		if err := r.ReconcileBank(ctx, "acme", testBank(1)); err == nil {
			t.Fatal("a state failure must be reported")
		}
	})
	t.Run("remove dead", func(t *testing.T) {
		store := newFakeStore()
		store.members["bank-1"] = []*bankstore.Member{deadMember()}
		store.removeErr = errors.New("postgres is down")
		r := newReconciler(t, store, &fakeLauncher{}, nil)
		if err := r.ReconcileBank(ctx, "acme", testBank(1)); err == nil {
			t.Fatal("a remove failure must be reported")
		}
	})
	t.Run("a dead sandbox that will not stop is still replaced", func(t *testing.T) {
		store := newFakeStore()
		store.members["bank-1"] = []*bankstore.Member{deadMember()}
		launcher := &fakeLauncher{stopErr: errors.New("setec is down")}
		r := newReconciler(t, store, launcher, nil)
		if err := r.ReconcileBank(ctx, "acme", testBank(1)); err != nil {
			t.Fatalf("ReconcileBank: %v", err)
		}
		if len(launcher.launched) != 1 {
			t.Fatal("the replacement must still launch")
		}
	})
	t.Run("drain", func(t *testing.T) {
		store := newFakeStore()
		store.members["bank-1"] = []*bankstore.Member{liveMember("m-1", bankstore.MemberIdle, 0), liveMember("m-2", bankstore.MemberIdle, 0)}
		store.stateErr = errors.New("postgres is down")
		r := newReconciler(t, store, &fakeLauncher{}, nil)
		if err := r.ReconcileBank(ctx, "acme", testBank(1)); err == nil {
			t.Fatal("a drain failure must be reported")
		}
	})
	t.Run("a drained sandbox that will not stop keeps its row", func(t *testing.T) {
		store := newFakeStore()
		m := liveMember("m-1", bankstore.MemberDraining, 0)
		store.members["bank-1"] = []*bankstore.Member{m}
		launcher := &fakeLauncher{stopErr: errors.New("setec is down")}
		r := newReconciler(t, store, launcher, nil)
		if err := r.ReconcileBank(ctx, "acme", testBank(0)); err == nil {
			t.Fatal("a stop failure must be reported")
		}
		if len(store.removed) != 0 {
			t.Fatal("a member whose sandbox still runs must keep its row")
		}
	})
}

// TestRunner_ATenantFailureIsLoggedAndTheRestContinue: a tenant whose banks
// cannot be listed does not stop the pass, and a canceled context ends it.
func TestRunner_ATenantFailureIsLoggedAndTheRestContinue(t *testing.T) {
	store := newFakeStore(testBank(1))
	store.listErr = errors.New("postgres is down")
	launcher := &fakeLauncher{}
	r := newReconciler(t, store, launcher, nil)
	runner, err := NewRunner(RunnerConfig{Reconciler: r, Tenants: &fakeTenants{ids: []string{"acme", "globex"}}})
	if err != nil {
		t.Fatal(err)
	}
	runner.Pass(context.Background())
	if len(launcher.launched) != 0 {
		t.Fatal("nothing launches when the banks cannot be listed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.listErr = nil
	runner.Pass(ctx)
	if len(launcher.launched) != 0 {
		t.Fatal("a canceled pass must not launch")
	}
}

func (f *fakeStore) GetMember(_ context.Context, _, memberID string) (*bankstore.Member, error) {
	for _, ms := range f.members {
		for _, m := range ms {
			if m.ID == memberID {
				return m, nil
			}
		}
	}
	return nil, bankstore.ErrNotFound
}
