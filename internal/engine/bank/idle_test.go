// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	bankstore "github.com/zeroroot-ai/gibson/internal/platform/bank"
)

// idleMember is an idle member with no job since idleFor ago.
func idleMember(id string, idleFor time.Duration) *bankstore.Member {
	m := liveMember(id, bankstore.MemberIdle, 0)
	m.IdleSince = testNow.Add(-idleFor)
	return m
}

// suspendedMember is a member that was suspended suspendedFor ago.
func suspendedMember(id string, suspendedFor time.Duration) *bankstore.Member {
	return &bankstore.Member{
		ID: id, BankID: "bank-1", State: bankstore.MemberSuspended, JobCap: 1,
		LastHeartbeat: testNow.Add(-suspendedFor), UpdatedAt: testNow.Add(-suspendedFor),
		CreatedAt: testNow.Add(-30 * 24 * time.Hour),
	}
}

// A member idle for the idle time is suspended; a member idle for less, a
// busy member and a member with no idle time are not (ADR-0119).
func TestReconcileBank_SuspendsAMemberIdleForTenMinutes(t *testing.T) {
	store := newFakeStore(testBank(4))
	store.members["bank-1"] = []*bankstore.Member{
		idleMember("old-idle", 11*time.Minute),
		idleMember("new-idle", 2*time.Minute),
		liveMember("busy", bankstore.MemberBusy, 1),
		liveMember("never-idle", bankstore.MemberIdle, 0),
	}
	l, ev := &fakeLauncher{}, &recordingEvents{}
	if err := newReconciler(t, store, l, ev).ReconcileBank(context.Background(), "acme", testBank(4)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if !reflect.DeepEqual(l.suspended, []string{"old-idle"}) || !reflect.DeepEqual(ev.suspended, []string{"old-idle"}) {
		t.Errorf("suspended = %v, events = %v, want [old-idle]", l.suspended, ev.suspended)
	}
	if len(l.launched) != 0 {
		t.Errorf("launched %v, want none", l.launched)
	}
}

// A suspended member is not dead, and it counts toward the running count, so
// no member is launched in its place. When jobs wait, it is resumed instead.
func TestReconcileBank_ResumesASuspendedMemberWhenJobsWait(t *testing.T) {
	store := newFakeStore(testBank(2))
	store.members["bank-1"] = []*bankstore.Member{
		suspendedMember("s1", time.Hour), suspendedMember("s2", time.Hour),
	}
	l, ev := &fakeLauncher{}, &recordingEvents{}
	quiet := newReconcilerWithJobs(t, store, l, &fakeJobs{}, ev)
	if err := quiet.ReconcileBank(context.Background(), "acme", testBank(2)); err != nil {
		t.Fatalf("no waiting job: %v", err)
	}
	if len(l.resumed)+len(l.launched)+len(ev.dead) != 0 {
		t.Fatalf("no waiting job: resumed %v, launched %v, dead %v; want nothing", l.resumed, l.launched, ev.dead)
	}

	jobs := &fakeJobs{unassigned: map[string]int64{"bank-1": 1}}
	busy := newReconcilerWithJobs(t, store, l, jobs, ev)
	if err := busy.ReconcileBank(context.Background(), "acme", testBank(2)); err != nil {
		t.Fatalf("one waiting job: %v", err)
	}
	if !reflect.DeepEqual(l.resumed, []string{"s1"}) || !reflect.DeepEqual(ev.resumed, []string{"s1"}) {
		t.Errorf("resumed = %v, events = %v, want [s1] for one waiting job", l.resumed, ev.resumed)
	}
	if len(l.launched) != 0 {
		t.Errorf("launched %v, want none while a member can resume", l.launched)
	}
}

// A member suspended for 7 days is recycled: stopped and removed. The next
// pass launches a new one when the bank count needs it.
func TestReconcileBank_RecyclesAMemberSuspendedForSevenDays(t *testing.T) {
	store := newFakeStore(testBank(1))
	store.members["bank-1"] = []*bankstore.Member{suspendedMember("stale", 8*24*time.Hour)}
	l, ev := &fakeLauncher{}, &recordingEvents{}
	r := newReconciler(t, store, l, ev)
	if err := r.ReconcileBank(context.Background(), "acme", testBank(1)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if !reflect.DeepEqual(l.stopped, []string{"stale"}) || !reflect.DeepEqual(store.removed, []string{"stale"}) {
		t.Errorf("stopped = %v, removed = %v, want [stale]", l.stopped, store.removed)
	}
	if len(l.launched) != 1 {
		t.Errorf("launched %v, want one member in place of the recycled one", l.launched)
	}
}

// When the bank shrinks, a suspended member goes before a live one.
func TestReconcileBank_ShrinksBySuspendedMembersFirst(t *testing.T) {
	store := newFakeStore(testBank(1))
	store.members["bank-1"] = []*bankstore.Member{
		liveMember("live", bankstore.MemberIdle, 0), suspendedMember("s", time.Hour),
	}
	l := &fakeLauncher{}
	if err := newReconciler(t, store, l, nil).ReconcileBank(context.Background(), "acme", testBank(1)); err != nil {
		t.Fatalf("ReconcileBank: %v", err)
	}
	if !reflect.DeepEqual(store.removed, []string{"s"}) {
		t.Errorf("removed = %v, want [s]", store.removed)
	}
}

// A failed suspend leaves the member as it was and reports the error.
func TestReconcileBank_AFailedSuspendKeepsTheMember(t *testing.T) {
	store := newFakeStore(testBank(1))
	store.members["bank-1"] = []*bankstore.Member{idleMember("m", time.Hour)}
	l := &fakeLauncher{suspendErr: errors.New("setec down")}
	err := newReconciler(t, store, l, nil).ReconcileBank(context.Background(), "acme", testBank(1))
	if err == nil {
		t.Fatal("a failed suspend reported no error")
	}
	if len(store.stateSet) != 0 {
		t.Errorf("state changed to %v after a failed suspend", store.stateSet)
	}
}

func TestResumeCount(t *testing.T) {
	for _, c := range []struct {
		waiting int64
		cap     int32
		want    int64
	}{{1, 1, 1}, {3, 2, 2}, {4, 2, 2}, {5, 0, 5}} {
		if got := resumeCount(c.waiting, c.cap); got != c.want {
			t.Errorf("resumeCount(%d, %d) = %d, want %d", c.waiting, c.cap, got, c.want)
		}
	}
}
