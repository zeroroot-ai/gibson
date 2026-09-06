// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package jobnode runs a mission's job node (ADR-0019 decisions 10, 12 and
// 15, gibson#1713): it opens a job on a bank, waits for each turn, has the
// acceptance verifier judge the work, sends the verifier's report back as
// the next turn while passes remain, and closes the job with a verdict.
//
// It owns the loop and nothing else. Opening, sending and closing go through
// JobOps, which the daemon backs with the job store. Judging goes through
// Verifier, which the daemon backs with an ordinary tool or agent dispatch.
// That split is what lets the loop be tested without a bank or a sandbox.
package jobnode

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/job"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"google.golang.org/protobuf/proto"
)

// JobOps is what the loop needs of the job store. job.Store satisfies it.
type JobOps interface {
	Open(ctx context.Context, tenantID string, in job.OpenInput) (*job.Job, error)
	Send(ctx context.Context, tenantID string, in job.SendInput) (*job.Input, error)
	Close(ctx context.Context, tenantID string, in job.CloseInput) (*job.Job, error)
	Get(ctx context.Context, tenantID, id string) (*job.Job, error)
	Events(ctx context.Context, tenantID, jobID string, since int64, limit int32) ([]*job.Event, error)
}

// Report is the verifier's structured answer.
type Report struct {
	Pass   bool    `json:"pass"`
	Score  float64 `json:"score"`
	Report string  `json:"report"`
}

// VerifyPayload is what the verifier is asked to judge.
type VerifyPayload struct {
	JobID        string               `json:"job_id"`
	Goal         string               `json:"goal"`
	Pass         int32                `json:"pass"`
	Inputs       []string             `json:"inputs"`
	Deliverables []*jobpb.Deliverable `json:"deliverables"`
}

// Verifier judges one pass. The daemon dispatches the named component as a
// normal tool or agent dispatch and parses its structured report.
type Verifier interface {
	Verify(ctx context.Context, component string, payload VerifyPayload) (Report, error)
}

// Input is one job node run.
type Input struct {
	TenantID     string
	MissionRunID string
	NodeID       string
	BankID       string
	Spec         *jobpb.JobSpec
	// Opener is the principal the job is opened and closed as: the mission,
	// which is why it may close (it is the scorer).
	Opener   job.Principal
	Ops      JobOps
	Verifier Verifier
	// PollInterval is how often the loop reads the job's events. Zero takes
	// DefaultPollInterval.
	PollInterval time.Duration
}

// Outcome is what the node produced.
type Outcome struct {
	Result job.Result
	Passes int32
	Report string
}

// DefaultPollInterval is how often the loop looks for the turn's end. A job
// moves at model speed, so a two-second poll is never the long pole.
const DefaultPollInterval = 2 * time.Second

// eventBatch bounds one Events read.
const eventBatch int32 = 200

// ErrClosedElsewhere is returned when a person or another scorer closed the
// job while the node was waiting on it. The node reports that close as its
// outcome rather than overwrite it.
var ErrClosedElsewhere = errors.New("jobnode: the job was closed by someone else")

// The two context keys the dashboard reads a run's jobs by (dashboard#1172).
const (
	contextMissionRunID = "mission_run_id"
	contextNodeID       = "node_id"
)

// Run drives one job node to a close and returns what it produced.
func Run(ctx context.Context, in Input) (Outcome, error) {
	if err := in.validate(); err != nil {
		return Outcome{}, err
	}
	interval := in.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	spec := stampContext(in.Spec, in.MissionRunID, in.NodeID)
	opened, err := in.Ops.Open(ctx, in.TenantID, job.OpenInput{BankID: in.BankID, Spec: spec, OpenedBy: in.Opener})
	if err != nil {
		return Outcome{}, fmt.Errorf("jobnode: open a job on bank %s: %w", in.BankID, err)
	}

	maxPasses := spec.GetAcceptance().GetMaxPasses()
	if maxPasses <= 0 {
		maxPasses = 1
	}
	var since int64
	var lastReport string
	for pass := int32(1); ; pass++ {
		turn, err := WaitForTurn(ctx, in.Ops, in.TenantID, opened.ID, since, interval)
		if err != nil {
			// The node's bound ended, or the store went away. The job must not
			// hang open on a bank waiting for a scorer that is gone.
			return abandon(ctx, in, opened.ID, pass, lastReport, err)
		}
		since = turn.Seq
		if turn.Closed {
			// Someone else closed it. Report their close, do not overwrite it.
			j, gerr := in.Ops.Get(ctx, in.TenantID, opened.ID)
			if gerr != nil {
				return Outcome{}, fmt.Errorf("jobnode: read a job closed elsewhere: %w", gerr)
			}
			result, rerr := job.ResultOf(j)
			if rerr != nil {
				return Outcome{}, fmt.Errorf("jobnode: %w", rerr)
			}
			return Outcome{Result: result, Passes: pass, Report: lastReport}, ErrClosedElsewhere
		}

		report, err := judge(ctx, in, opened.ID, pass, spec)
		if err != nil {
			return abandon(ctx, in, opened.ID, pass, lastReport, err)
		}
		lastReport = report.Report
		accepted := report.Pass && report.Score >= spec.GetAcceptance().GetPassingScore()
		switch {
		case accepted:
			return closeWith(ctx, in, opened.ID, job.VerdictAccomplished, report.Score, pass, lastReport)
		case pass >= maxPasses:
			return closeWith(ctx, in, opened.ID, job.VerdictFailed, report.Score, pass, lastReport)
		}
		// Another pass: the report is the next turn.
		if _, err := in.Ops.Send(ctx, in.TenantID, job.SendInput{
			JobID: opened.ID, Kind: job.InputTurn, Message: report.Report, Sender: in.Opener,
		}); err != nil {
			return abandon(ctx, in, opened.ID, pass, lastReport, fmt.Errorf("send the verifier's report: %w", err))
		}
	}
}

func (in Input) validate() error {
	switch {
	case in.Ops == nil:
		return errors.New("jobnode: Ops is required")
	case in.Verifier == nil:
		return errors.New("jobnode: Verifier is required")
	case in.TenantID == "" || in.BankID == "":
		return errors.New("jobnode: a tenant and a bank are required")
	case in.Spec == nil || in.Spec.GetGoal() == "":
		return errors.New("jobnode: a job spec with a goal is required")
	case in.Opener.ID == "":
		return errors.New("jobnode: an opener is required")
	}
	return nil
}

// stampContext copies the spec and names the run and the node on it, so a
// reader finds a run's jobs by spec.context (dashboard#1172).
func stampContext(spec *jobpb.JobSpec, missionRunID, nodeID string) *jobpb.JobSpec {
	out, _ := proto.Clone(spec).(*jobpb.JobSpec)
	if out.Context == nil {
		out.Context = map[string]*commonpb.TypedValue{}
	}
	if missionRunID != "" {
		out.Context[contextMissionRunID] = &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: missionRunID}}
	}
	if nodeID != "" {
		out.Context[contextNodeID] = &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: nodeID}}
	}
	return out
}

// TurnEnd is what WaitForTurn saw: the sequence it read up to, and whether
// the job closed rather than paused.
type TurnEnd struct {
	Seq    int64
	Closed bool
}

// EventReader is the one read WaitForTurn needs. JobOps satisfies it.
type EventReader interface {
	Events(ctx context.Context, tenantID, jobID string, since int64, limit int32) ([]*job.Event, error)
}

// WaitForTurn polls the job's events until the member reports waiting (the
// turn ended and the member wants input) or the job closes. It is the wait
// the job node and a DelegateToAgent caller share.
func WaitForTurn(ctx context.Context, ops EventReader, tenantID, jobID string, since int64, interval time.Duration) (TurnEnd, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		events, err := ops.Events(ctx, tenantID, jobID, since, eventBatch)
		if err != nil {
			return TurnEnd{}, fmt.Errorf("read the job's events: %w", err)
		}
		for _, ev := range events {
			since = ev.Seq
			switch {
			case ev.Kind == job.EventClosed:
				return TurnEnd{Seq: since, Closed: true}, nil
			case ev.Kind == job.EventState && ev.State == job.StateWaiting:
				return TurnEnd{Seq: since}, nil
			}
		}
		select {
		case <-ctx.Done():
			return TurnEnd{}, fmt.Errorf("the bound ended while waiting on the turn: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// judge asks the verifier. A spec with no acceptance step accepts the first
// turn: nobody was named to judge it, so the work stands as delivered.
func judge(ctx context.Context, in Input, jobID string, pass int32, spec *jobpb.JobSpec) (Report, error) {
	verifier := spec.GetAcceptance().GetVerifierComponent()
	if verifier == "" {
		return Report{Pass: true, Score: 1}, nil
	}
	j, err := in.Ops.Get(ctx, in.TenantID, jobID)
	if err != nil {
		return Report{}, fmt.Errorf("read the job before judging it: %w", err)
	}
	report, err := in.Verifier.Verify(ctx, verifier, VerifyPayload{
		JobID: jobID, Goal: spec.GetGoal(), Pass: pass,
		Inputs: spec.GetInputs(), Deliverables: j.Deliverables,
	})
	if err != nil {
		return Report{}, fmt.Errorf("verifier %s on pass %d: %w", verifier, pass, err)
	}
	return report, nil
}

func closeWith(ctx context.Context, in Input, jobID string, verdict job.Verdict, score float64, pass int32, report string) (Outcome, error) {
	closed, err := in.Ops.Close(ctx, in.TenantID, job.CloseInput{JobID: jobID, Verdict: verdict, Score: score, Closer: in.Opener})
	if err != nil {
		return Outcome{}, fmt.Errorf("jobnode: close job %s as %s: %w", jobID, verdict, err)
	}
	result, err := job.ResultOf(closed)
	if err != nil {
		return Outcome{}, fmt.Errorf("jobnode: %w", err)
	}
	return Outcome{Result: result, Passes: pass, Report: report}, nil
}

// abandon closes the job as abandoned when the node cannot finish it, so a
// bank is not left holding a job whose scorer is gone. The close runs on a
// bound that keeps the caller's values but drops its cancellation, because
// the caller's own bound may be the thing that ended.
func abandon(ctx context.Context, in Input, jobID string, pass int32, report string, cause error) (Outcome, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if _, err := in.Ops.Close(ctx, in.TenantID, job.CloseInput{JobID: jobID, Verdict: job.VerdictAbandoned, Closer: in.Opener}); err != nil {
		return Outcome{Passes: pass, Report: report}, fmt.Errorf("jobnode: %w (and the job could not be abandoned: %w)", cause, err)
	}
	return Outcome{Passes: pass, Report: report}, fmt.Errorf("jobnode: %w", cause)
}
