// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package job

import (
	"encoding/json"
	"fmt"
	"time"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// Result is what a closed job hands back (ADR-0019 decisions 11 and 16,
// gibson#1712): the verdict and the score the scorer gave, what the member
// delivered, the Claude session that holds the transcript, and how many
// passes it took. It is the record a delegating caller reads, and it is
// written to the session store under ResultKey so a reader that only has
// the job id finds it there.
type Result struct {
	JobID           string        `json:"job_id"`
	BankID          string        `json:"bank_id"`
	MemberID        string        `json:"member_id,omitempty"`
	Verdict         Verdict       `json:"verdict"`
	Score           float64       `json:"score"`
	Deliverables    []Deliverable `json:"deliverables"`
	ClaudeSessionID string        `json:"claude_session_id,omitempty"`
	Attempts        int32         `json:"attempts"`
	OpenedAt        time.Time     `json:"opened_at"`
	ClosedAt        time.Time     `json:"closed_at"`
}

// Deliverable is one thing a member handed back, in the shape the wire uses.
type Deliverable struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
	URL  string `json:"url,omitempty"`
}

// ResultKey is the session-store key a job's result is written under. The
// transcript chunks live under "<job_id>" and "<job_id>/<n>" (the member
// driver's contract), so the result takes its own suffix beside them.
func ResultKey(jobID string) string { return jobID + "/result" }

// ResultOf reads a closed job's result. A job that is not closed has no
// result yet, and asking for one is a programming error a caller should
// see, so it is refused rather than answered with an empty verdict.
func ResultOf(j *Job) (Result, error) {
	if j == nil {
		return Result{}, fmt.Errorf("%w: no job", ErrInvalid)
	}
	if j.State != StateClosed {
		return Result{}, fmt.Errorf("%w: job %s is %s, and only a closed job has a result", ErrInvalid, j.ID, j.State)
	}
	out := Result{
		JobID: j.ID, BankID: j.BankID, MemberID: j.MemberID,
		Verdict: j.Verdict, Score: j.Score,
		Deliverables:    make([]Deliverable, 0, len(j.Deliverables)),
		ClaudeSessionID: j.ClaudeSessionID, Attempts: j.Attempts,
		OpenedAt: j.OpenedAt, ClosedAt: j.ClosedAt,
	}
	for _, d := range j.Deliverables {
		out.Deliverables = append(out.Deliverables, Deliverable{
			Kind: deliverableKindName(d.GetKind()), Ref: d.GetRef(), URL: d.GetUrl(),
		})
	}
	return out, nil
}

// Encode renders the result as the JSON the session store holds.
func (r Result) Encode() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("job: encode result of %s: %w", r.JobID, err)
	}
	return b, nil
}

// deliverableKindName renders the wire kind as the name the console and the
// result record use.
func deliverableKindName(k jobpb.DeliverableKind) string {
	switch k {
	case jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH:
		return "push_branch"
	case jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST:
		return "merge_request"
	case jobpb.DeliverableKind_DELIVERABLE_KIND_NONE:
		return "none"
	case jobpb.DeliverableKind_DELIVERABLE_KIND_UNSPECIFIED:
		return "unspecified"
	default:
		return "unspecified"
	}
}
