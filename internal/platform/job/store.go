// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package job

import (
	"context"
	"fmt"
	"strings"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// Store is the daemon's single source of truth for jobs, their inputs and
// their events. Every method is tenant-scoped: the tenant selects the database,
// so one tenant's job id can never resolve in another.
type Store interface {
	// Open records a new job and its opening event. The job is OPEN with no
	// member when the queue must place it, or assigned when MemberID names a
	// member with a free slot.
	Open(ctx context.Context, tenantID string, in OpenInput) (*Job, error)

	// Get returns one job, or ErrNotFound.
	Get(ctx context.Context, tenantID, id string) (*Job, error)

	// List returns one page of the tenant's jobs, newest first.
	List(ctx context.Context, tenantID string, filter ListFilter, page Page) ([]*Job, string, error)

	// Send appends an input to an open job and records the event. A WAITING
	// job returns to WORKING. It returns ErrClosed for a closed job.
	Send(ctx context.Context, tenantID string, in SendInput) (*Input, error)

	// Close records the verdict and the score, appends the wrap-up input, and
	// records the closing event. It returns ErrClosed when the job is already
	// closed, so two scorers cannot give one job two verdicts.
	Close(ctx context.Context, tenantID string, in CloseInput) (*Job, error)

	// Claim hands the oldest queued job of a bank to a member and marks it
	// taken, in one transaction. It returns (nil, nil) when the queue is
	// empty, which is the ordinary case and not an error.
	Claim(ctx context.Context, tenantID, bankID, memberID string) (*Job, error)

	// PendingInputs returns the inputs of a member's jobs that it has not
	// acknowledged, oldest first. A member that reconnects reads them again.
	PendingInputs(ctx context.Context, tenantID, memberID string, limit int32) ([]*Input, error)

	// Acknowledge marks one input as run, so it is not delivered again.
	Acknowledge(ctx context.Context, tenantID, inputID string) error

	// SetState records a state change the member reported, and its event.
	SetState(ctx context.Context, tenantID, jobID string, state State, claudeSessionID string) (*Job, error)

	// AddDeliverable records one outward result the member performed.
	AddDeliverable(ctx context.Context, tenantID, jobID string, d *jobpb.Deliverable) (*Job, error)

	// Events returns the events of one job after since, oldest first.
	Events(ctx context.Context, tenantID, jobID string, since int64, limit int32) ([]*Event, error)

	// ReleaseMember clears the member from every job it holds that is not
	// closed, so the next Claim of any member of the bank hands the job back
	// with its claude_session_id kept. It reports how many jobs it released.
	// The reconciler calls it for a dead member (gibson#1709).
	ReleaseMember(ctx context.Context, tenantID, memberID string) (int64, error)

	// Stale returns open jobs of one bank whose last input is older than
	// staleSeconds. The reconciler closes them as abandoned.
	Stale(ctx context.Context, tenantID, bankID string, staleSeconds int64, limit int32) ([]*Job, error)
}

// ValidateSpec checks that a JobSpec could describe work a member can do, and
// fills what the daemon defaults.
//
// It is deliberately narrow. The daemon enforces exactly the fields it reads:
// the repositories it builds worktrees from and the credential names the
// per-turn grant is scoped to. `context` is free-form and is not inspected —
// anything the daemon must enforce lives in a declared field, which is the rule
// the proto comment states.
func ValidateSpec(spec *jobpb.JobSpec) error {
	if spec == nil {
		return fmt.Errorf("%w: a job needs a spec", ErrInvalid)
	}
	if strings.TrimSpace(spec.GetGoal()) == "" && len(spec.GetRepositories()) == 0 {
		return fmt.Errorf("%w: a job needs a goal or at least one repository", ErrInvalid)
	}
	seen := map[string]struct{}{}
	for i, r := range spec.GetRepositories() {
		switch {
		case strings.TrimSpace(r.GetName()) == "":
			return fmt.Errorf("%w: repositories[%d]: name is required, it is the worktree directory", ErrInvalid, i)
		case strings.TrimSpace(r.GetConnectorRef()) == "":
			return fmt.Errorf("%w: repositories[%d]: connector_ref is required, or the driver has no credential to push with", ErrInvalid, i)
		case strings.TrimSpace(r.GetProject()) == "":
			return fmt.Errorf("%w: repositories[%d]: project is required", ErrInvalid, i)
		case r.GetDeliverable() == jobpb.DeliverableKind_DELIVERABLE_KIND_UNSPECIFIED:
			return fmt.Errorf("%w: repositories[%d]: deliverable is required, say none when nothing should leave the sandbox", ErrInvalid, i)
		}
		if _, dup := seen[r.GetName()]; dup {
			return fmt.Errorf("%w: repositories[%d]: name %q is declared twice; two worktrees cannot share a directory", ErrInvalid, i, r.GetName())
		}
		seen[r.GetName()] = struct{}{}
	}
	for i, name := range spec.GetCredentialNames() {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: credential_names[%d] is empty", ErrInvalid, i)
		}
	}
	if a := spec.GetAcceptance(); a != nil {
		if a.GetPassingScore() < 0 || a.GetPassingScore() > 1 {
			return fmt.Errorf("%w: acceptance.passing_score %.2f must be between 0 and 1", ErrInvalid, a.GetPassingScore())
		}
		if a.GetMaxPasses() < 0 {
			return fmt.Errorf("%w: acceptance.max_passes %d must not be negative", ErrInvalid, a.GetMaxPasses())
		}
		if a.GetVerifierComponent() == "" && a.GetMaxPasses() > 1 {
			return fmt.Errorf("%w: acceptance.max_passes %d needs a verifier_component; there is nothing to run a second pass against",
				ErrInvalid, a.GetMaxPasses())
		}
	}
	return nil
}

// Validate checks an open request.
func (in *OpenInput) Validate() error {
	if strings.TrimSpace(in.BankID) == "" {
		return fmt.Errorf("%w: bank_id is required", ErrInvalid)
	}
	if err := validatePrincipal(in.OpenedBy, "opened_by"); err != nil {
		return err
	}
	return ValidateSpec(in.Spec)
}

// Validate checks a send request and defaults the kind.
func (in *SendInput) Validate() error {
	if strings.TrimSpace(in.JobID) == "" {
		return fmt.Errorf("%w: job_id is required", ErrInvalid)
	}
	if strings.TrimSpace(in.Message) == "" {
		return fmt.Errorf("%w: message is required", ErrInvalid)
	}
	if in.Kind == "" {
		in.Kind = InputTurn
	}
	if !IsInputKind(in.Kind) {
		return fmt.Errorf("%w: input kind %q is not one of turn, answer, wrap_up", ErrInvalid, in.Kind)
	}
	return validatePrincipal(in.Sender, "sender")
}

// Validate checks a close request.
func (in *CloseInput) Validate() error {
	if strings.TrimSpace(in.JobID) == "" {
		return fmt.Errorf("%w: job_id is required", ErrInvalid)
	}
	if !IsVerdict(in.Verdict) {
		return fmt.Errorf("%w: verdict %q is not one of accomplished, failed, abandoned", ErrInvalid, in.Verdict)
	}
	if in.Score < 0 || in.Score > 1 {
		return fmt.Errorf("%w: score %.2f must be between 0 and 1", ErrInvalid, in.Score)
	}
	return validatePrincipal(in.Closer, "closer")
}

func validatePrincipal(p Principal, field string) error {
	switch p.Kind {
	case PrincipalUser, PrincipalTenant, PrincipalComponent, PrincipalService:
	default:
		return fmt.Errorf("%w: %s.kind %q is not a principal kind", ErrInvalid, field, p.Kind)
	}
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("%w: %s.id is required", ErrInvalid, field)
	}
	return nil
}

// clampPageSize bounds a requested page size. Zero takes the default; above the
// maximum is capped rather than refused.
func clampPageSize(size int32) int32 {
	switch {
	case size <= 0:
		return DefaultPageSize
	case size > MaxPageSize:
		return MaxPageSize
	default:
		return size
	}
}
