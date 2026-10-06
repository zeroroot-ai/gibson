// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"strings"
	"testing"
	"time"
)

// A recovery notice reaches the inbox of the member, with the time of the
// state for a resume, and a plain notice for a restart.
func TestMemberControl_ReportRecovery(t *testing.T) {
	c := NewMemberControl()
	taken := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	c.ReportRecovery("acme", "m-1", taken)
	c.ReportRecovery("acme", "m-1", time.Time{})

	got := c.Drain("acme", "m-1")
	if len(got) != 2 {
		t.Fatalf("drained %d inputs, want 2", len(got))
	}
	if got[0].GetJobId() != RecoveryJobID || !strings.Contains(got[0].GetMessage(), "2026-10-06T12:00:00Z") {
		t.Errorf("resume notice = %v", got[0])
	}
	if !strings.Contains(got[1].GetMessage(), "restarted from the workspace") {
		t.Errorf("restart notice = %v", got[1])
	}
	if len(c.Drain("acme", "m-2")) != 0 {
		t.Error("another member must get no notice")
	}
}
