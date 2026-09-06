// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package job

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// TestResultOf_ReadsAClosedJob asserts the result carries the verdict, the
// score, every deliverable, the session and the passes, and that it survives
// the session-store encoding.
func TestResultOf_ReadsAClosedJob(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	j := &Job{
		ID: "job-1", BankID: "bank-1", MemberID: "m-1", State: StateClosed,
		Verdict: VerdictAccomplished, Score: 0.9, ClaudeSessionID: "sess-1", Attempts: 2,
		OpenedAt: now.Add(-time.Hour), ClosedAt: now,
		Deliverables: []*jobpb.Deliverable{
			{Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH, Ref: "fix/build", Url: "https://x/tree/fix"},
			{Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST, Ref: "!7"},
		},
	}
	r, err := ResultOf(j)
	if err != nil {
		t.Fatalf("ResultOf: %v", err)
	}
	if r.Verdict != VerdictAccomplished || r.Score != 0.9 || r.ClaudeSessionID != "sess-1" || r.Attempts != 2 {
		t.Errorf("result = %+v", r)
	}
	if len(r.Deliverables) != 2 || r.Deliverables[0].Kind != "push_branch" || r.Deliverables[1].Kind != "merge_request" || r.Deliverables[1].URL != "" {
		t.Errorf("deliverables = %+v", r.Deliverables)
	}

	data, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.JobID != "job-1" || back.Verdict != VerdictAccomplished || len(back.Deliverables) != 2 || !back.ClosedAt.Equal(now) {
		t.Errorf("decoded = %+v", back)
	}
	if ResultKey("job-1") != "job-1/result" {
		t.Errorf("key = %q", ResultKey("job-1"))
	}
}

// TestResultOf_RefusesAnOpenJob asserts only a closed job has a result.
func TestResultOf_RefusesAnOpenJob(t *testing.T) {
	if _, err := ResultOf(&Job{ID: "job-1", State: StateWorking}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if _, err := ResultOf(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	// A job with no deliverables still has a result, with an empty list
	// rather than a null.
	r, err := ResultOf(&Job{ID: "job-2", State: StateClosed, Verdict: VerdictFailed})
	if err != nil || r.Deliverables == nil || len(r.Deliverables) != 0 {
		t.Fatalf("result = %+v, %v", r, err)
	}
	for k, want := range map[jobpb.DeliverableKind]string{
		jobpb.DeliverableKind_DELIVERABLE_KIND_NONE:        "none",
		jobpb.DeliverableKind_DELIVERABLE_KIND_UNSPECIFIED: "unspecified",
		jobpb.DeliverableKind(99):                          "unspecified",
	} {
		if got := deliverableKindName(k); got != want {
			t.Errorf("deliverableKindName(%v) = %q, want %q", k, got, want)
		}
	}
}
