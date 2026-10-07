// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A member whose sandbox recovered gets one notice for each new recovery
// count, and no second notice for a count that it saw.
func TestReportRecovery_EachNewCountOnce(t *testing.T) {
	c := newMemberClient()
	taken := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	c.recovery = SessionRecovery{Kind: RecoveryResumed, StateTaken: taken, Count: 1}

	var (
		mu  sync.Mutex
		got []SessionRecovery
	)
	d := AgentDispatch{Tenant: "acme", OnResumed: func(r SessionRecovery) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r)
	}}
	l := newAgentLauncher(t, c)
	ctx := context.Background()

	seen := l.reportRecovery(ctx, "sbx-1", d, 0)
	seen = l.reportRecovery(ctx, "sbx-1", d, seen)
	c.mu.Lock()
	c.recovery.Count = 2
	c.mu.Unlock()
	seen = l.reportRecovery(ctx, "sbx-1", d, seen)

	if seen != 2 || len(got) != 2 {
		t.Fatalf("seen = %d, notices = %d; want 2 and 2", seen, len(got))
	}
	if !got[0].StateTaken.Equal(taken) {
		t.Errorf("state taken = %v, want %v", got[0].StateTaken, taken)
	}
}

// A sandbox that never recovered gives no notice.
func TestReportRecovery_NoRecoveryNoNotice(t *testing.T) {
	called := false
	d := AgentDispatch{Tenant: "acme", OnResumed: func(SessionRecovery) { called = true }}
	if seen := newAgentLauncher(t, newMemberClient()).reportRecovery(context.Background(), "sbx-1", d, 0); seen != 0 || called {
		t.Fatalf("seen = %d, called = %v", seen, called)
	}
}

// LaunchMember refuses a dispatch with no receiver of the resume event.
func TestLaunchMember_NeedsAResumeReceiver(t *testing.T) {
	if _, err := newAgentLauncher(t, newMemberClient()).LaunchMember(context.Background(), memberSpec(), AgentDispatch{Tenant: "acme"}); err == nil {
		t.Fatal("want an error for a dispatch with no OnResumed")
	}
}
