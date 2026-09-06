// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
)

func memberEventsOver(t *testing.T, store *fakeBankStore) (*memberEvents, *liveagents.Registry) {
	t.Helper()
	reg := liveagents.NewRegistry()
	d := &daemonImpl{logger: testObsLogger(), liveAgents: reg}
	return &memberEvents{daemon: d, stores: func() (bank.Store, error) { return store, nil }}, reg
}

func backlogOf(t *testing.T, reg *liveagents.Registry, runID string) []string {
	t.Helper()
	backlog, _, cancel, err := reg.Subscribe("acme", runID, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	out := make([]string, 0, len(backlog))
	for _, ev := range backlog {
		out = append(out, string(ev.Data))
	}
	return out
}

// TestMemberEvents_PublishReachesTheMembersRun asserts a line lands on the
// live run the member's row names, and that an unknown member, a member with
// no live run, and a daemon with no banks drop the line without failing the
// caller.
func TestMemberEvents_PublishReachesTheMembersRun(t *testing.T) {
	store := newFakeBankStore()
	store.members["bank-1"] = []*bank.Member{{ID: "m-1", BankID: "bank-1", AgentRunID: "run-1"}, {ID: "m-2", BankID: "bank-1", AgentRunID: "run-gone"}}
	e, reg := memberEventsOver(t, store)
	_, fin := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "claude", StartedAt: time.Now()})
	defer fin()
	ctx := context.Background()

	e.PublishMemberEvent(ctx, "acme", "m-1", []byte(`{"type":"job_opened","job_id":"j-1"}`+"\n"))
	e.PublishMemberEvent(ctx, "acme", "m-2", []byte("dropped: no live run\n"))
	e.PublishMemberEvent(ctx, "acme", "m-9", []byte("dropped: no member\n"))
	got := backlogOf(t, reg, "run-1")
	if len(got) != 1 || !strings.Contains(got[0], "job_opened") {
		t.Fatalf("backlog = %q", got)
	}

	dark := &memberEvents{daemon: &daemonImpl{logger: testObsLogger(), liveAgents: reg}}
	dark.PublishMemberEvent(ctx, "acme", "m-1", []byte("dropped: no banks\n"))
	if got := backlogOf(t, reg, "run-1"); len(got) != 1 {
		t.Fatalf("a daemon with no banks must drop the line, backlog = %q", got)
	}
}

// TestMemberEvents_ReportMemberStatusStoresAndAnnounces asserts a heartbeat
// updates the row and puts a member_status line on the stream, that a state
// a member may not claim is refused, and that a daemon with no banks refuses.
func TestMemberEvents_ReportMemberStatusStoresAndAnnounces(t *testing.T) {
	store := newFakeBankStore()
	store.members["bank-1"] = []*bank.Member{{ID: "m-1", BankID: "bank-1", AgentRunID: "run-1", State: bank.MemberLaunching}}
	e, reg := memberEventsOver(t, store)
	_, fin := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "claude", StartedAt: time.Now()})
	defer fin()
	ctx := context.Background()

	err := e.ReportMemberStatus(ctx, "acme", "m-1", &bankpb.MemberStatus{
		State: bankpb.MemberState_MEMBER_STATE_BUSY, JobsInFlight: 1, Cap: 2, ClaudeVersion: "2.1.257",
	})
	if err != nil {
		t.Fatalf("ReportMemberStatus: %v", err)
	}
	if m := store.members["bank-1"][0]; m.State != bank.MemberBusy || m.JobsInFlight != 1 || m.ClaudeVersion != "2.1.257" {
		t.Errorf("member = %+v", m)
	}
	got := backlogOf(t, reg, "run-1")
	if len(got) != 1 || !strings.Contains(got[0], `"type":"member_status"`) || !strings.Contains(got[0], `"state":"busy"`) {
		t.Fatalf("backlog = %q", got)
	}

	if err := e.ReportMemberStatus(ctx, "acme", "m-9", &bankpb.MemberStatus{State: bankpb.MemberState_MEMBER_STATE_IDLE}); err == nil {
		t.Error("an unknown member must be refused")
	}
	dark := &memberEvents{daemon: &daemonImpl{logger: testObsLogger(), liveAgents: reg}}
	if err := dark.ReportMemberStatus(ctx, "acme", "m-1", &bankpb.MemberStatus{State: bankpb.MemberState_MEMBER_STATE_IDLE}); err == nil {
		t.Error("a daemon with no banks must refuse")
	}
}

// TestMemberStateFromProto asserts only the states a member may claim map.
func TestMemberStateFromProto(t *testing.T) {
	for wire, want := range map[bankpb.MemberState]bank.MemberState{
		bankpb.MemberState_MEMBER_STATE_IDLE:          bank.MemberIdle,
		bankpb.MemberState_MEMBER_STATE_BUSY:          bank.MemberBusy,
		bankpb.MemberState_MEMBER_STATE_NEEDS_SIGN_IN: bank.MemberNeedsSignIn,
		bankpb.MemberState_MEMBER_STATE_DEAD:          "",
		bankpb.MemberState_MEMBER_STATE_DRAINING:      "",
		bankpb.MemberState_MEMBER_STATE_LAUNCHING:     "",
		bankpb.MemberState_MEMBER_STATE_UNSPECIFIED:   "",
		bankpb.MemberState(99):                        "",
	} {
		if got := memberStateFromProto(wire); got != want {
			t.Errorf("memberStateFromProto(%v) = %q, want %q", wire, got, want)
		}
	}
}

// TestLazyMemberSource_RefusesWithoutAPool asserts the console's member
// source answers not-found before the pool is up, so the rows still list.
func TestLazyMemberSource_RefusesWithoutAPool(t *testing.T) {
	src := &lazyMemberSource{daemon: &daemonImpl{}}
	if _, err := src.MemberByRun(context.Background(), "acme", "run-1"); !errors.Is(err, bank.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
