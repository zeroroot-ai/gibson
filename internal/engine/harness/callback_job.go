// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package harness — callback_job.go
//
// The member-facing half of the job surface (ADR-0019, gibson#1711).
//
// A bank member never accepts an inbound connection. It pulls: it takes the
// next queued job of its own bank, it follows its own inbox, and it reports
// what it did. Every one of those calls carries the member's BASE grant, which
// reaches nothing tenant-shaped.
//
// Each input the member pulls carries a grant of its own — the TURN grant,
// minted from the authority of whoever sent that input. That is what keeps one
// sender's authority out of the next sender's turn inside a sandbox that serves
// both.
package harness

import (
	"context"
	"encoding/json"
	"errors"

	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// JobSurface is what the member callbacks need from the job store. It is
// narrower than job.Store on purpose: these handlers serve an untrusted
// sandbox, and the seam should not hand it more than it can use.
type JobSurface interface {
	Open(ctx context.Context, tenantID string, in job.OpenInput) (*job.Job, error)
	Send(ctx context.Context, tenantID string, in job.SendInput) (*job.Input, error)
	Events(ctx context.Context, tenantID, jobID string, since int64, limit int32) ([]*job.Event, error)
	Claim(ctx context.Context, tenantID, bankID, memberID string) (*job.Job, error)
	Get(ctx context.Context, tenantID, id string) (*job.Job, error)
	PendingInputs(ctx context.Context, tenantID, memberID string, limit int32) ([]*job.Input, error)
	Acknowledge(ctx context.Context, tenantID, inputID string) error
	SetState(ctx context.Context, tenantID, jobID string, state job.State, claudeSessionID string) (*job.Job, error)
	AddDeliverable(ctx context.Context, tenantID, jobID string, d *jobpb.Deliverable) (*job.Job, error)
}

// TurnGrantMinter mints the per-turn grant an input is delivered with. The
// daemon backs it with the capability-grant minter; tests fake it.
type TurnGrantMinter interface {
	Mint(req capabilitygrant.MintRequest) (string, error)
}

// MemberLookup resolves the member a callback is coming from, and the bank it
// belongs to. The daemon backs it with the bank store.
//
// It exists because a member's callback names no member: the identity comes
// from the grant, not from the body, so the daemon has to look up which member
// that identity belongs to. A body field would let one member act as another.
type MemberLookup interface {
	// MemberByRun returns the member id and its bank id for a mission run. An
	// error means the run is not a member's.
	MemberByRun(ctx context.Context, tenantID, missionRunID string) (memberID, bankID string, err error)
}

// ErrNotAMember is what a MemberLookup answers for a run that backs no member.
// It is a named error so the callbacks can tell "not a member" from an outage:
// the first is a refusal the caller may learn, the second is never read as
// "not a member", because that reading would let a member act unbounded
// while the bank store is down.
var ErrNotAMember = errors.New("harness: this run backs no member")

// ErrNoBankSurface is what every member seam answers on a callback service
// the daemon has not wired a bank store, a job store or a grant minter into.
//
// The seams default to it so they are never nil. A member callback then fails
// closed with FailedPrecondition, and the credential check reads the caller
// as not a member, which is true of every caller on a daemon with no banks.
var ErrNoBankSurface = errors.New("harness: this daemon serves no banks")

// noBankSurface is the default behind every member seam. See ErrNoBankSurface.
type noBankSurface struct{}

func (noBankSurface) Open(context.Context, string, job.OpenInput) (*job.Job, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) Send(context.Context, string, job.SendInput) (*job.Input, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) Events(context.Context, string, string, int64, int32) ([]*job.Event, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) Claim(context.Context, string, string, string) (*job.Job, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) Get(context.Context, string, string) (*job.Job, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) PendingInputs(context.Context, string, string, int32) ([]*job.Input, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) Acknowledge(context.Context, string, string) error { return ErrNoBankSurface }

func (noBankSurface) SetState(context.Context, string, string, job.State, string) (*job.Job, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) AddDeliverable(context.Context, string, string, *jobpb.Deliverable) (*job.Job, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) MemberByRun(context.Context, string, string) (memberID, bankID string, err error) {
	return "", "", ErrNoBankSurface
}

func (noBankSurface) Mint(capabilitygrant.MintRequest) (string, error) { return "", ErrNoBankSurface }

func (noBankSurface) PublishMemberEvent(context.Context, string, string, []byte) {}

// MemberEventSink carries the job lines the daemon emits onto a member's
// console stream (ADR-0019 decision 13, gibson#1716): a console following a
// member sees the jobs it takes, the inputs it gets, the states it reports and
// the deliverables it records, in order with the agent's own output.
type MemberEventSink interface {
	// PublishMemberEvent appends one NDJSON line to the member's stream. A
	// member with no live stream is not an error to the callback that
	// produced the line: the line is for a viewer, and the work stands.
	PublishMemberEvent(ctx context.Context, tenantID, memberID string, line []byte)
}

// WithMemberEventSink wires where the job lines go.
func WithMemberEventSink(sink MemberEventSink) CallbackServiceOption {
	return func(c *HarnessCallbackService) { c.memberEvents = sink }
}

// memberLine renders one console line. The shapes are the ones the dashboard
// renders (dashboard#1170), keyed by type.
func memberLine(fields map[string]any) []byte {
	b, err := json.Marshal(fields)
	if err != nil {
		// Every value is a string, a number or a slice of strings, so this
		// cannot fail; a line that did would be a programming error worth a
		// loud log rather than a silent drop.
		return []byte(`{"type":"job_line_unrenderable"}` + "\n")
	}
	return append(b, '\n')
}

func (s *HarnessCallbackService) emitMemberLine(ctx context.Context, tenantID, memberID string, fields map[string]any) {
	s.memberEvents.PublishMemberEvent(ctx, tenantID, memberID, memberLine(fields))
}

// WithMemberControl shares the sign-in control queue with the bank service,
// which enqueues what this service delivers (gibson#1715).
func WithMemberControl(c *MemberControl) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		if c != nil {
			s.memberControl = c
		}
	}
}

// WithJobSurface wires the job store the member callbacks read and write.
func WithJobSurface(s JobSurface) CallbackServiceOption {
	return func(c *HarnessCallbackService) { c.jobs = s }
}

// WithTurnGrantMinter wires the minter that stamps a per-turn grant onto each
// delivered input.
func WithTurnGrantMinter(m TurnGrantMinter) CallbackServiceOption {
	return func(c *HarnessCallbackService) { c.turnGrants = m }
}

// WithMemberLookup wires the resolution from a mission run to the member that
// backs it.
func WithMemberLookup(l MemberLookup) CallbackServiceOption {
	return func(c *HarnessCallbackService) { c.members = l }
}

// inboxPollInterval is how often SubscribeInput looks for new input. The store
// is the source of truth and a job moves at human or model speed, so a short
// poll is simpler than a notification channel and cannot miss an input: every
// read asks for everything still unacknowledged.
const inboxPollInterval = 2 * time.Second

// memberInboxBatch bounds one inbox read.
const memberInboxBatch int32 = 20

// callerMember resolves which member is calling, from the mission run on the
// request context and never from the request body.
func (s *HarnessCallbackService) callerMember(ctx context.Context, info *harnesspb.ContextInfo) (tenantID, memberID, bankID string, err error) {
	tenantID = auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return "", "", "", status.Error(codes.PermissionDenied, "no tenant in context")
	}
	runID := info.GetMissionRunId()
	if runID == "" {
		return "", "", "", status.Error(codes.InvalidArgument, "context.mission_run_id is required to identify the calling member")
	}
	memberID, bankID, err = s.members.MemberByRun(ctx, tenantID, runID)
	switch {
	case errors.Is(err, ErrNoBankSurface):
		return "", "", "", status.Error(codes.FailedPrecondition, "this daemon serves no banks")
	case errors.Is(err, ErrNotAMember):
		// A run that is not a member's is not an error to explain: the caller
		// is not a member, and that is all it may learn.
		return "", "", "", status.Error(codes.PermissionDenied, "this run is not a bank member")
	case err != nil:
		return "", "", "", status.Errorf(codes.Unavailable, "resolve the calling member: %v", err)
	}
	return tenantID, memberID, bankID, nil
}

// PullJob hands the calling member the next queued job of its own bank.
//
// The member names no bank: the bank comes from the member, which comes from
// the run on the verified context. A member cannot pull from a bank it does not
// belong to, because it never gets to say which bank.
func (s *HarnessCallbackService) PullJob(ctx context.Context, req *harnesspb.PullJobRequest) (*harnesspb.PullJobResponse, error) {
	tenantID, memberID, bankID, err := s.callerMember(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	claimed, err := s.jobs.Claim(ctx, tenantID, bankID, memberID)
	if err != nil {
		if errors.Is(err, job.ErrNoFreeSlot) {
			// The member asked for work it has no room for. That is the
			// member's own bookkeeping being behind, not a failure.
			return &harnesspb.PullJobResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "pull a job: %v", err)
	}
	if claimed == nil {
		// An empty queue. The response carries no job and no error.
		return &harnesspb.PullJobResponse{}, nil
	}
	s.logger.InfoContext(ctx, "member pulled a job",
		"member_id", memberID, "bank_id", bankID, "job_id", claimed.ID)
	s.emitMemberLine(ctx, tenantID, memberID, map[string]any{
		"type": "job_opened", "job_id": claimed.ID, "goal": claimed.Spec.GetGoal(),
	})
	return &harnesspb.PullJobResponse{Job: jobToWire(claimed)}, nil
}

// SubscribeInput streams the calling member's unacknowledged inputs, each with
// the grant of the dispatch that sent it.
//
// The stream is outbound-only and the member pulls it: the sandbox never
// accepts a connection (ADR-0019 decision 6). An input stays on the stream
// until the member reports the job state that acknowledges it, so a reconnect
// replays exactly what was not run.
//
// One subscriber per member. The member driver is the one reader, and it hands
// each turn's grant to the localhost MCP server itself (ADR-0019 decision 2).
// A second reader would race the first: an input the driver acknowledged by
// reporting the job state before the second reader's next poll would never
// reach it, and a turn grant that reached only one of the two processes is a
// turn that cannot run. So a second concurrent stream for the same member is
// refused, and the refusal names the rule.
func (s *HarnessCallbackService) SubscribeInput(req *harnesspb.SubscribeInputRequest, stream harnesspb.HarnessCallbackService_SubscribeInputServer) error {
	ctx := stream.Context()
	tenantID, memberID, _, err := s.callerMember(ctx, req.GetContext())
	if err != nil {
		return err
	}
	inboxKey := tenantID + "/" + memberID
	if _, taken := s.memberInboxes.LoadOrStore(inboxKey, struct{}{}); taken {
		return status.Error(codes.AlreadyExists,
			"this member's inbox already has a subscriber; one process reads the inbox and hands each turn grant to the MCP server")
	}
	defer s.memberInboxes.Delete(inboxKey)

	// delivered remembers what this stream has already sent, so a reconnect
	// replays an unacknowledged input but a live stream does not send it twice
	// every poll.
	delivered := map[string]struct{}{}
	ticker := time.NewTicker(inboxPollInterval)
	defer ticker.Stop()
	for {
		// Control inputs first: a sign-in word must not wait behind a job's
		// turns, and it carries no grant because it carries no authority.
		for _, control := range s.memberControl.Drain(tenantID, memberID) {
			if serr := stream.Send(&harnesspb.SubscribeInputResponse{Input: control}); serr != nil {
				return status.Errorf(codes.Unavailable, "deliver a control input: %v", serr)
			}
		}
		pending, perr := s.jobs.PendingInputs(ctx, tenantID, memberID, memberInboxBatch)
		if perr != nil {
			return status.Errorf(codes.Internal, "read the member inbox: %v", perr)
		}
		for _, in := range pending {
			if _, sent := delivered[in.ID]; sent {
				continue
			}
			wire, gerr := s.inputWithTurnGrant(ctx, tenantID, in)
			if gerr != nil {
				return gerr
			}
			if serr := stream.Send(&harnesspb.SubscribeInputResponse{Input: wire}); serr != nil {
				return status.Errorf(codes.Unavailable, "deliver an input: %v", serr)
			}
			delivered[in.ID] = struct{}{}
			s.emitMemberLine(ctx, tenantID, memberID, map[string]any{
				"type": "job_input", "job_id": in.JobID, "kind": string(in.Kind),
				"sender": turnGrantSubject(in.Sender), "message": firstRunes(in.Message, 200),
			})
		}
		select {
		case <-ctx.Done():
			// The member went away. It will reconnect and read the same
			// unacknowledged inputs.
			return nil
		case <-ticker.C:
		}
	}
}

// inputWithTurnGrant renders one input for delivery and mints its turn grant.
//
// The grant is minted at DELIVERY, not when the input was stored: a grant that
// sat in a table between the send and the turn would be a standing credential
// with a table for a home, and its lifetime would be the queue's depth rather
// than the turn's.
func (s *HarnessCallbackService) inputWithTurnGrant(ctx context.Context, tenantID string, in *job.Input) (*jobpb.Input, error) {
	wire := &jobpb.Input{
		Id: in.ID, JobId: in.JobID, Message: in.Message,
		Sender: senderToWire(in.Sender), SentAt: timestamppb.New(in.SentAt),
		Kind: inputKindToWire(in.Kind),
	}
	j, err := s.jobs.Get(ctx, tenantID, in.JobID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the job an input belongs to: %v", err)
	}
	grant, err := s.turnGrants.Mint(capabilitygrant.MintRequest{
		// The subject is the SENDER, not the member: the turn acts with the
		// authority of whoever asked for it, which is the whole point of a
		// per-turn grant.
		Subject:        turnGrantSubject(in.Sender),
		Tenant:         tenantID,
		MissionID:      j.BankID,
		TaskID:         in.JobID,
		RecipientClass: "agent",
		AllowedRPCs:    TurnGrantRPCs(),
	})
	if errors.Is(err, ErrNoBankSurface) {
		return nil, status.Error(codes.FailedPrecondition, "this daemon cannot mint a turn grant")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint the turn grant: %v", err)
	}
	wire.Grant = grant
	return wire, nil
}

// turnGrantSubject renders the sender as a grant subject. A component's id is
// already a typed principal; anything else is a person or a service, and the
// subject says which.
func turnGrantSubject(p job.Principal) string {
	if p.Kind == job.PrincipalComponent {
		return p.ID
	}
	return string(p.Kind) + ":" + p.ID
}

// ReportJobState records the state a member reports, and acknowledges the
// inputs that state accounts for.
//
// A member reports WORKING or WAITING. It never reports CLOSED: a scorer closes
// a job, and the store refuses the closed state through this path.
func (s *HarnessCallbackService) ReportJobState(ctx context.Context, req *harnesspb.ReportJobStateRequest) (*harnesspb.ReportJobStateResponse, error) {
	tenantID, memberID, _, err := s.callerMember(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if err := s.assertJobHeldByMember(ctx, tenantID, memberID, req.GetJobId()); err != nil {
		return nil, err
	}
	state := wireToJobState(req.GetState())
	if state != job.StateWorking && state != job.StateWaiting {
		return nil, status.Error(codes.InvalidArgument, "a member reports working or waiting; a scorer closes a job")
	}
	if _, err := s.jobs.SetState(ctx, tenantID, req.GetJobId(), state, req.GetClaudeSessionId()); err != nil {
		return nil, jobCallbackError(err)
	}
	// A member that says it is working on a job has run the inputs it was
	// given for it. Acknowledging them here is what stops a reconnect from
	// replaying a turn the model already took.
	s.emitMemberLine(ctx, tenantID, memberID, map[string]any{
		"type": "job_state", "job_id": req.GetJobId(), "state": string(state),
	})
	if err := s.acknowledgeInputsFor(ctx, tenantID, memberID, req.GetJobId()); err != nil {
		return nil, err
	}
	return &harnesspb.ReportJobStateResponse{}, nil
}

// ReportDeliverable records one outward result the driver performed.
func (s *HarnessCallbackService) ReportDeliverable(ctx context.Context, req *harnesspb.ReportDeliverableRequest) (*harnesspb.ReportDeliverableResponse, error) {
	tenantID, memberID, _, err := s.callerMember(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if err := s.assertJobHeldByMember(ctx, tenantID, memberID, req.GetJobId()); err != nil {
		return nil, err
	}
	if req.GetDeliverable() == nil {
		return nil, status.Error(codes.InvalidArgument, "deliverable is required")
	}
	if _, err := s.jobs.AddDeliverable(ctx, tenantID, req.GetJobId(), req.GetDeliverable()); err != nil {
		return nil, jobCallbackError(err)
	}
	s.logger.InfoContext(ctx, "member reported a deliverable",
		"member_id", memberID, "job_id", req.GetJobId(),
		"kind", req.GetDeliverable().GetKind().String(), "ref", req.GetDeliverable().GetRef())
	d := req.GetDeliverable()
	s.emitMemberLine(ctx, tenantID, memberID, map[string]any{
		"type": "job_deliverable", "job_id": req.GetJobId(),
		"kind": deliverableKindName(d.GetKind()), "ref": d.GetRef(), "url": d.GetUrl(),
	})
	return &harnesspb.ReportDeliverableResponse{}, nil
}

// assertJobHeldByMember refuses a report about a job the caller does not hold.
// Without it a member could report state or deliverables on another member's
// job, and the only thing standing between them would be the job id.
func (s *HarnessCallbackService) assertJobHeldByMember(ctx context.Context, tenantID, memberID, jobID string) error {
	if jobID == "" {
		return status.Error(codes.InvalidArgument, "job_id is required")
	}
	j, err := s.jobs.Get(ctx, tenantID, jobID)
	if err != nil {
		return jobCallbackError(err)
	}
	if j.MemberID != memberID {
		// NotFound, not PermissionDenied: a member must not learn that another
		// member's job exists.
		return status.Error(codes.NotFound, "no such job")
	}
	return nil
}

// acknowledgeInputsFor marks the member's unacknowledged inputs for one job as
// run.
func (s *HarnessCallbackService) acknowledgeInputsFor(ctx context.Context, tenantID, memberID, jobID string) error {
	pending, err := s.jobs.PendingInputs(ctx, tenantID, memberID, memberInboxBatch)
	if err != nil {
		return status.Errorf(codes.Internal, "read the member inbox: %v", err)
	}
	for _, in := range pending {
		if in.JobID != jobID {
			continue
		}
		if aerr := s.jobs.Acknowledge(ctx, tenantID, in.ID); aerr != nil {
			return status.Errorf(codes.Internal, "acknowledge an input: %v", aerr)
		}
	}
	return nil
}

// jobCallbackError maps a store error to what a member may learn.
func jobCallbackError(err error) error {
	switch {
	case errors.Is(err, ErrNoBankSurface):
		return status.Error(codes.FailedPrecondition, "this daemon serves no jobs")
	case errors.Is(err, job.ErrNotFound):
		return status.Error(codes.NotFound, "no such job")
	case errors.Is(err, job.ErrClosed):
		return status.Error(codes.FailedPrecondition, "the job is closed")
	case errors.Is(err, job.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "job store: %v", err)
	}
}

// ---- wire conversion -------------------------------------------------------

func jobToWire(j *job.Job) *jobpb.Job {
	return &jobpb.Job{
		Id: j.ID, BankId: j.BankID, MemberId: j.MemberID,
		State: jobStateToWire(j.State), Spec: j.Spec,
		ClaudeSessionId: j.ClaudeSessionID,
		OpenedBy:        senderToWire(j.OpenedBy),
		OpenedAt:        timestamppb.New(j.OpenedAt),
		LastInputAt:     timestamppb.New(j.LastInputAt),
		Deliverables:    j.Deliverables,
		Attempts:        j.Attempts,
	}
}

func senderToWire(p job.Principal) *commonpb.Principal {
	kind := commonpb.Principal_KIND_USER
	switch p.Kind {
	case job.PrincipalTenant:
		kind = commonpb.Principal_KIND_TENANT
	case job.PrincipalComponent:
		kind = commonpb.Principal_KIND_COMPONENT
	case job.PrincipalService:
		kind = commonpb.Principal_KIND_SERVICE
	case job.PrincipalUser:
		// The default above. Named so a new kind fails the exhaustive check
		// rather than quietly rendering as a person.
	}
	return &commonpb.Principal{Kind: kind, Id: p.ID}
}

func jobStateToWire(s job.State) jobpb.JobState {
	switch s {
	case job.StateOpen:
		return jobpb.JobState_JOB_STATE_OPEN
	case job.StateWorking:
		return jobpb.JobState_JOB_STATE_WORKING
	case job.StateWaiting:
		return jobpb.JobState_JOB_STATE_WAITING
	case job.StateClosed:
		return jobpb.JobState_JOB_STATE_CLOSED
	default:
		return jobpb.JobState_JOB_STATE_UNSPECIFIED
	}
}

func wireToJobState(s jobpb.JobState) job.State {
	switch s {
	case jobpb.JobState_JOB_STATE_OPEN:
		return job.StateOpen
	case jobpb.JobState_JOB_STATE_WORKING:
		return job.StateWorking
	case jobpb.JobState_JOB_STATE_WAITING:
		return job.StateWaiting
	case jobpb.JobState_JOB_STATE_CLOSED:
		return job.StateClosed
	case jobpb.JobState_JOB_STATE_UNSPECIFIED:
		// No state. A member that reports none is refused by name.
		return ""
	default:
		return ""
	}
}

func inputKindToWire(k job.InputKind) jobpb.InputKind {
	switch k {
	case job.InputAnswer:
		return jobpb.InputKind_INPUT_KIND_ANSWER
	case job.InputWrapUp:
		return jobpb.InputKind_INPUT_KIND_WRAP_UP
	case job.InputTurn:
		return jobpb.InputKind_INPUT_KIND_TURN
	default:
		return jobpb.InputKind_INPUT_KIND_TURN
	}
}

// firstRunes returns at most n runes of s, so a console line carries a
// preview and never a whole prompt.
func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// deliverableKindName renders a deliverable kind the way the console reads it.
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
