// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package job is the daemon's store for jobs: the unit of work a bank member
// holds (ADR-0019, gibson#1706).
//
// A job is one persistent Claude Code session with its own worktrees. It is
// opened by a structured input, stays open across turns, and is closed by a
// scorer — never by the worker. Every input is recorded in order and delivered
// outbound to the member that holds the job.
//
// The types here are the daemon's own. The wire types in gibson.job.v1 are
// mapped at the handler edge. The one exception is JobSpec, which is stored as
// the proto the opener sent: the daemon reads two of its fields to mint a
// grant, and a member must see exactly what was declared, so re-modelling it
// would be a second copy of a contract that already exists.
package job

import (
	"errors"
	"time"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// Sentinel errors returned by Store.
var (
	// ErrNotFound is returned when no job has the given id.
	ErrNotFound = errors.New("job not found")
	// ErrInvalid is returned when the input could not describe a job that can
	// run: no goal and no repository, a repository with no connector, an
	// acceptance with a score outside 0..1.
	ErrInvalid = errors.New("invalid job")
	// ErrClosed is returned when an input or a close is sent to a job that a
	// scorer already closed. A closed job is final: reopening it would give
	// one job two verdicts.
	ErrClosed = errors.New("job is closed")
	// ErrNoFreeSlot is returned when a job is pinned to a member that is
	// already at its cap.
	ErrNoFreeSlot = errors.New("member has no free slot")
)

// State is where a job is in its life. The values are the ones the published
// docs use.
type State string

const (
	// StateOpen — opened, waiting for a member to take it.
	StateOpen State = "open"
	// StateWorking — a member is running a turn on it.
	StateWorking State = "working"
	// StateWaiting — it asked a question, or finished a turn, and waits for
	// the next input.
	StateWaiting State = "waiting"
	// StateClosed — a scorer closed it. Verdict and score are set.
	StateClosed State = "closed"
)

// IsState reports whether s names a job state.
func IsState(s State) bool {
	switch s {
	case StateOpen, StateWorking, StateWaiting, StateClosed:
		return true
	default:
		return false
	}
}

// Verdict is the outcome a scorer gives when it closes a job.
type Verdict string

const (
	// VerdictAccomplished — the job met its acceptance.
	VerdictAccomplished Verdict = "accomplished"
	// VerdictFailed — the job did not meet its acceptance.
	VerdictFailed Verdict = "failed"
	// VerdictAbandoned — the job went idle past the bank's stale limit, or its
	// bank was deleted.
	VerdictAbandoned Verdict = "abandoned"
)

// IsVerdict reports whether v names a verdict a scorer may give.
func IsVerdict(v Verdict) bool {
	switch v {
	case VerdictAccomplished, VerdictFailed, VerdictAbandoned:
		return true
	default:
		return false
	}
}

// InputKind is what an input asks the member to do.
type InputKind string

const (
	// InputTurn — run one more turn with this message.
	InputTurn InputKind = "turn"
	// InputAnswer — this message answers the question the job asked.
	InputAnswer InputKind = "answer"
	// InputWrapUp — the final turn after a close. Commit, push, open the merge
	// request, summarize. Only the daemon sends it.
	InputWrapUp InputKind = "wrap_up"
)

// IsInputKind reports whether k names an input kind.
func IsInputKind(k InputKind) bool {
	return k == InputTurn || k == InputAnswer || k == InputWrapUp
}

// EventKind is what a recorded event reports.
type EventKind string

// The event kinds, in the order a job's life records them.
const (
	EventOpened      EventKind = "opened"
	EventInput       EventKind = "input"
	EventState       EventKind = "state"
	EventDeliverable EventKind = "deliverable"
	EventClosed      EventKind = "closed"
)

// PrincipalKind is the class of a principal that opened a job or sent an input.
type PrincipalKind string

// The principal kinds a job accepts.
const (
	PrincipalUser      PrincipalKind = "user"
	PrincipalTenant    PrincipalKind = "tenant"
	PrincipalComponent PrincipalKind = "component"
	PrincipalService   PrincipalKind = "service"
)

// Principal is who did something: opened a job, sent an input, closed a job.
type Principal struct {
	Kind PrincipalKind
	ID   string
}

// Job is one persistent Claude Code session on a bank member.
type Job struct {
	ID              string
	BankID          string
	MemberID        string
	State           State
	Spec            *jobpb.JobSpec
	ClaudeSessionID string
	OpenedBy        Principal
	OpenedAt        time.Time
	LastInputAt     time.Time
	ClosedAt        time.Time
	Verdict         Verdict
	Score           float64
	Deliverables    []*jobpb.Deliverable
	Attempts        int32
	Spilled         bool
}

// Input is one message to a job. The grant is never a field: it is minted when
// the input is delivered and lives only in that delivery.
type Input struct {
	ID             string
	JobID          string
	Seq            int64
	Kind           InputKind
	Message        string
	Sender         Principal
	SentAt         time.Time
	AcknowledgedAt time.Time
}

// Event is one recorded change on a job, for the event stream.
type Event struct {
	JobID       string
	Seq         int64
	Kind        EventKind
	OccurredAt  time.Time
	State       State
	Verdict     Verdict
	Score       float64
	Message     string
	Input       *Input
	Deliverable *jobpb.Deliverable
}

// OpenInput opens a job on a bank.
type OpenInput struct {
	BankID string
	// MemberID pins the job to one member. Empty lets the queue pick one.
	MemberID string
	Spec     *jobpb.JobSpec
	OpenedBy Principal
}

// SendInput appends one message to an open job.
type SendInput struct {
	JobID   string
	Kind    InputKind
	Message string
	Sender  Principal
}

// CloseInput closes a job with a verdict and a score.
type CloseInput struct {
	JobID   string
	Verdict Verdict
	Score   float64
	Closer  Principal
}

// ListFilter narrows a job listing. Every set field narrows it further.
type ListFilter struct {
	BankID   string
	MemberID string
	State    State
}

// Page is one page of a listing.
type Page struct {
	Size  int32
	Token string
}

// Page sizes.
const (
	DefaultPageSize int32 = 50
	MaxPageSize     int32 = 200
)
