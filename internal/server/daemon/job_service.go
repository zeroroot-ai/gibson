// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — job_service.go
//
// jobServer implements gibson.job.v1.JobService: opening jobs on a bank,
// sending them input, closing them with a verdict, and reading them back
// (ADR-0019, gibson#1710).
//
// The rule the whole design rests on lives here: the worker never closes its
// own job. CloseJob is authorized against can_close, which a member's can_send
// grant does not imply, so a member given the right to ask a question cannot
// use it to declare its own work finished.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// jobEventPollInterval is how often StreamJobEvents looks for new events after
// it has drained the backlog. The store is the source of truth and a job moves
// at human or model speed, so a short poll is simpler than a notification
// channel and cannot miss an event: every read is "everything after seq".
const jobEventPollInterval = 2 * time.Second

// jobServer serves JobService over the job store.
type jobServer struct {
	jobpb.UnimplementedJobServiceServer

	jobs       job.Store
	banks      bank.Store
	authorizer authz.Authorizer
	logger     *slog.Logger
	events     harness.MemberEventSink
	sessions   harness.SessionContextStore
}

// JobServerConfig is the constructor input. All three sources are required:
// without the bank store a job could be opened on a bank that does not exist,
// and without the authorizer no per-resource decision can be made.
type JobServerConfig struct {
	Jobs       job.Store
	Banks      bank.Store
	Authorizer authz.Authorizer
	Logger     *slog.Logger
	// MemberEvents carries job_closed onto the holding member's console stream
	// (gibson#1716). Required: a close nobody can see is a close a viewer
	// cannot act on.
	MemberEvents harness.MemberEventSink
	// Sessions is where a closed job's result is written, under
	// job.ResultKey (gibson#1712), beside the transcript the member archived.
	// Required: a result that is only in the jobs table is one a reader with
	// nothing but the job id cannot find.
	Sessions harness.SessionContextStore
}

// NewJobServer constructs the JobService.
func NewJobServer(cfg JobServerConfig) (jobpb.JobServiceServer, error) {
	if cfg.Jobs == nil {
		return nil, errors.New("daemon: NewJobServer: Jobs store is required")
	}
	if cfg.Banks == nil {
		return nil, errors.New("daemon: NewJobServer: Banks store is required")
	}
	if cfg.MemberEvents == nil {
		return nil, errors.New("job service: MemberEvents is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("job service: Sessions is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("daemon: NewJobServer: Authorizer is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &jobServer{
		jobs: cfg.Jobs, banks: cfg.Banks, authorizer: cfg.Authorizer,
		logger:   cfg.Logger.With("component", "job_service"),
		events:   cfg.MemberEvents,
		sessions: cfg.Sessions,
	}, nil
}

func (s *jobServer) tenant(ctx context.Context) (string, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok || t.String() == "" {
		return "", status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return t.String(), nil
}

// principal is the caller as a job principal. It is who opened a job, who sent
// an input and who closed it, so it comes from the verified identity and never
// from the request.
func (s *jobServer) principal(ctx context.Context) (job.Principal, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return job.Principal{}, status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	return job.Principal{Kind: principalKindOf(id.Subject), ID: id.Subject}, nil
}

// principalKindOf reads the class of a subject. A component's subject is a
// typed FGA principal (ADR-0045); anything else is a person or a service
// account, and the two are told apart by the credential the identity carries,
// not by the subject, so a subject alone maps to user.
func principalKindOf(subject string) job.PrincipalKind {
	for _, prefix := range []string{"agent_principal:", "tool_principal:", "plugin_principal:"} {
		if strings.HasPrefix(subject, prefix) {
			return job.PrincipalComponent
		}
	}
	return job.PrincipalUser
}

// authorize makes the per-resource decision for every rule whose object is
// derived from a request field. ext-authz cannot decode a body, so it passes
// those through and the handler decides (gibson#1245).
func (s *jobServer) authorize(ctx context.Context, relation, objectType, id string) error {
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		return status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	allowed, err := s.authorizer.Check(ctx, fgaUserFromIdentity(identity), relation, objectType+":"+id)
	if err != nil {
		s.logger.ErrorContext(ctx, "job authorization check failed",
			"relation", relation, "object", objectType+":"+id, "error", err)
		return status.Error(codes.Unavailable, "authorization service unavailable")
	}
	if !allowed {
		// NotFound, never PermissionDenied: a caller with no right must not
		// learn that the bank or the job exists.
		return status.Errorf(codes.NotFound, "no such %s", objectType)
	}
	return nil
}

// OpenJob opens a job on a bank and hands it to a member, or queues it.
func (s *jobServer) OpenJob(ctx context.Context, req *jobpb.OpenJobRequest) (*jobpb.OpenJobResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "can_send", "bank", req.GetBankId()); err != nil {
		return nil, err
	}
	opener, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	// The bank must exist before a job names it, so a typo answers NotFound
	// rather than a foreign-key error.
	if _, err := s.banks.Get(ctx, tenant, req.GetBankId()); err != nil {
		return nil, bankStoreError(err)
	}

	opened, err := s.jobs.Open(ctx, tenant, job.OpenInput{
		BankID: req.GetBankId(), MemberID: req.GetMemberId(),
		Spec: req.GetSpec(), OpenedBy: opener,
	})
	if err != nil {
		return nil, jobStoreError(err)
	}

	// The opener may send and close its own job. The tuples are what make that
	// true for a principal that holds nothing on the bank — a mission node, a
	// verification agent — and they name the bank as the job's parent so the
	// bank's own rights carry down.
	tuples := []authz.Tuple{
		{User: "bank:" + opened.BankID, Relation: "parent", Object: "job:" + opened.ID},
		{User: fgaUserForPrincipal(opener), Relation: "opened_by", Object: "job:" + opened.ID},
	}
	if err := s.authorizer.Write(ctx, tuples); err != nil {
		// A job nobody can send to or close is not a job. Roll it back.
		if _, closeErr := s.jobs.Close(ctx, tenant, job.CloseInput{
			JobID: opened.ID, Verdict: job.VerdictAbandoned, Closer: opener,
		}); closeErr != nil {
			s.logger.ErrorContext(ctx, "job tuples failed and the job could not be closed",
				"job_id", opened.ID, "write_error", err, "close_error", closeErr)
		}
		return nil, status.Errorf(codes.Internal, "write job authorization: %v", err)
	}

	s.logger.InfoContext(ctx, "job opened",
		"job_id", opened.ID, "bank_id", opened.BankID, "member_id", opened.MemberID)
	return &jobpb.OpenJobResponse{Job: jobToProto(opened)}, nil
}

// SendInput appends the next message to an open job.
func (s *jobServer) SendInput(ctx context.Context, req *jobpb.SendInputRequest) (*jobpb.SendInputResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "can_send", "job", req.GetJobId()); err != nil {
		return nil, err
	}
	sender, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	kind := inputKindFromProto(req.GetKind())
	if kind == job.InputWrapUp {
		// The wrap-up turn is the daemon's, appended by Close. A client that
		// could send one would make a job perform its deliverables without a
		// verdict.
		return nil, status.Error(codes.InvalidArgument, "wrap_up is sent by the daemon after a close, never by a client")
	}
	in, err := s.jobs.Send(ctx, tenant, job.SendInput{
		JobID: req.GetJobId(), Kind: kind, Message: req.GetMessage(), Sender: sender,
	})
	if err != nil {
		return nil, jobStoreError(err)
	}
	return &jobpb.SendInputResponse{Input: inputToProto(in)}, nil
}

// CloseJob records the verdict and the score. Only a scorer may call it.
func (s *jobServer) CloseJob(ctx context.Context, req *jobpb.CloseJobRequest) (*jobpb.CloseJobResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "can_close", "job", req.GetJobId()); err != nil {
		return nil, err
	}
	closer, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	closed, err := s.jobs.Close(ctx, tenant, job.CloseInput{
		JobID:   req.GetJobId(),
		Verdict: verdictFromProto(req.GetVerdict()),
		Score:   req.GetScore(),
		Closer:  closer,
	})
	if err != nil {
		return nil, jobStoreError(err)
	}
	s.logger.InfoContext(ctx, "job closed",
		"job_id", closed.ID, "verdict", string(closed.Verdict), "score", closed.Score)
	s.recordResult(ctx, tenant, closed)
	if closed.MemberID != "" {
		line, _ := json.Marshal(map[string]any{
			"type": "job_closed", "job_id": closed.ID,
			"verdict": string(verdictFromProto(req.GetVerdict())), "score": req.GetScore(),
		})
		s.events.PublishMemberEvent(ctx, tenant, closed.MemberID, append(line, '\n'))
	}
	return &jobpb.CloseJobResponse{Job: jobToProto(closed)}, nil
}

// GetJob returns one job.
func (s *jobServer) GetJob(ctx context.Context, req *jobpb.GetJobRequest) (*jobpb.GetJobResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "can_read", "job", req.GetJobId()); err != nil {
		return nil, err
	}
	j, err := s.jobs.Get(ctx, tenant, req.GetJobId())
	if err != nil {
		return nil, jobStoreError(err)
	}
	return &jobpb.GetJobResponse{Job: jobToProto(j)}, nil
}

// ListJobs returns one page of the caller tenant's jobs, newest first.
func (s *jobServer) ListJobs(ctx context.Context, req *jobpb.ListJobsRequest) (*jobpb.ListJobsResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	jobs, next, err := s.jobs.List(ctx, tenant,
		job.ListFilter{
			BankID:   req.GetBankId(),
			MemberID: req.GetMemberId(),
			State:    stateFromProto(req.GetState()),
		},
		job.Page{Size: req.GetPageSize(), Token: req.GetPageToken()})
	if err != nil {
		return nil, jobStoreError(err)
	}
	out := make([]*jobpb.Job, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, jobToProto(j))
	}
	return &jobpb.ListJobsResponse{Jobs: out, NextPageToken: next}, nil
}

// StreamJobEvents replays the backlog after since_seq, then follows the job
// live until it closes or the client goes away.
func (s *jobServer) StreamJobEvents(req *jobpb.StreamJobEventsRequest, stream jobpb.JobService_StreamJobEventsServer) error {
	ctx := stream.Context()
	tenant, err := s.tenant(ctx)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, "can_read", "job", req.GetJobId()); err != nil {
		return err
	}

	// The client echoes a sequence this server issued, so it is bounded by the
	// job's own event count.
	since := int64(req.GetSinceSeq()) //nolint:gosec // an echoed per-job sequence
	ticker := time.NewTicker(jobEventPollInterval)
	defer ticker.Stop()
	for {
		events, err := s.jobs.Events(ctx, tenant, req.GetJobId(), since, job.MaxPageSize)
		if err != nil {
			return jobStoreError(err)
		}
		for _, e := range events {
			if sendErr := stream.Send(&jobpb.StreamJobEventsResponse{Event: eventToProto(e)}); sendErr != nil {
				return status.Errorf(codes.Unavailable, "send job event: %v", sendErr)
			}
			since = e.Seq
			if e.Kind == job.EventClosed {
				// The proto says the stream ends after the closing event.
				return nil
			}
		}
		select {
		case <-ctx.Done():
			// The client went away. That is not an error.
			return nil
		case <-ticker.C:
		}
	}
}

// jobStoreError maps a store error to the gRPC code a caller can act on.
func jobStoreError(err error) error {
	switch {
	case errors.Is(err, job.ErrNotFound):
		return status.Error(codes.NotFound, "no such job")
	case errors.Is(err, job.ErrClosed):
		return status.Error(codes.FailedPrecondition, "the job is closed")
	case errors.Is(err, job.ErrNoFreeSlot):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, job.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "job store: %v", err)
	}
}

// fgaUserForPrincipal renders a job principal as an FGA user. A component is
// already a typed principal ref; a person is a user.
func fgaUserForPrincipal(p job.Principal) string {
	if p.Kind == job.PrincipalComponent {
		return p.ID
	}
	return "user:" + p.ID
}

// ---- wire conversion -------------------------------------------------------

func jobToProto(j *job.Job) *jobpb.Job {
	out := &jobpb.Job{
		Id:              j.ID,
		BankId:          j.BankID,
		MemberId:        j.MemberID,
		State:           stateToProto(j.State),
		Spec:            j.Spec,
		ClaudeSessionId: j.ClaudeSessionID,
		OpenedBy:        principalToProto(j.OpenedBy),
		OpenedAt:        timestamppb.New(j.OpenedAt),
		LastInputAt:     timestamppb.New(j.LastInputAt),
		Verdict:         verdictToProto(j.Verdict),
		Score:           j.Score,
		Deliverables:    j.Deliverables,
		Attempts:        j.Attempts,
	}
	if !j.ClosedAt.IsZero() {
		out.ClosedAt = timestamppb.New(j.ClosedAt)
	}
	return out
}

// inputToProto renders an input for a client. The grant is never set: it is
// minted at delivery and belongs to the member, not to a reader.
func inputToProto(in *job.Input) *jobpb.Input {
	return &jobpb.Input{
		Id:      in.ID,
		JobId:   in.JobID,
		Message: in.Message,
		Sender:  principalToProto(in.Sender),
		SentAt:  timestamppb.New(in.SentAt),
		Kind:    inputKindToProto(in.Kind),
	}
}

func eventToProto(e *job.Event) *jobpb.JobEvent {
	out := &jobpb.JobEvent{
		// A per-job sequence, counted from one by the store, so it is always
		// small and positive.
		Seq:         uint64(e.Seq), //nolint:gosec // a per-job sequence is never negative
		OccurredAt:  timestamppb.New(e.OccurredAt),
		Kind:        eventKindToProto(e.Kind),
		JobId:       e.JobID,
		State:       stateToProto(e.State),
		Verdict:     verdictToProto(e.Verdict),
		Score:       e.Score,
		Message:     e.Message,
		Deliverable: e.Deliverable,
	}
	if e.Input != nil {
		out.Input = inputToProto(e.Input)
	}
	return out
}

func principalToProto(p job.Principal) *commonpb.Principal {
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

func stateFromProto(s jobpb.JobState) job.State {
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
		// No filter. The empty state matches every job.
		return ""
	default:
		return ""
	}
}

func stateToProto(s job.State) jobpb.JobState {
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

// verdictFromProto maps the wire enum. An unspecified verdict maps to the
// empty verdict, which Validate refuses by name, so a caller that forgets it
// gets a clear error rather than a default outcome.
func verdictFromProto(v jobpb.JobVerdict) job.Verdict {
	switch v {
	case jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED:
		return job.VerdictAccomplished
	case jobpb.JobVerdict_JOB_VERDICT_FAILED:
		return job.VerdictFailed
	case jobpb.JobVerdict_JOB_VERDICT_ABANDONED:
		return job.VerdictAbandoned
	case jobpb.JobVerdict_JOB_VERDICT_UNSPECIFIED:
		// The empty verdict, which Validate refuses by name. A default here
		// would pick an outcome for a caller that named none.
		return ""
	default:
		return ""
	}
}

func verdictToProto(v job.Verdict) jobpb.JobVerdict {
	switch v {
	case job.VerdictAccomplished:
		return jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED
	case job.VerdictFailed:
		return jobpb.JobVerdict_JOB_VERDICT_FAILED
	case job.VerdictAbandoned:
		return jobpb.JobVerdict_JOB_VERDICT_ABANDONED
	default:
		return jobpb.JobVerdict_JOB_VERDICT_UNSPECIFIED
	}
}

// inputKindFromProto maps the wire enum. Unspecified means a turn, which is
// what the proto says.
func inputKindFromProto(k jobpb.InputKind) job.InputKind {
	switch k {
	case jobpb.InputKind_INPUT_KIND_ANSWER:
		return job.InputAnswer
	case jobpb.InputKind_INPUT_KIND_WRAP_UP:
		return job.InputWrapUp
	case jobpb.InputKind_INPUT_KIND_TURN, jobpb.InputKind_INPUT_KIND_UNSPECIFIED:
		// Unspecified means a turn, which is what the proto says.
		return job.InputTurn
	default:
		return job.InputTurn
	}
}

func inputKindToProto(k job.InputKind) jobpb.InputKind {
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

func eventKindToProto(k job.EventKind) jobpb.JobEventKind {
	switch k {
	case job.EventOpened:
		return jobpb.JobEventKind_JOB_EVENT_KIND_OPENED
	case job.EventInput:
		return jobpb.JobEventKind_JOB_EVENT_KIND_INPUT
	case job.EventState:
		return jobpb.JobEventKind_JOB_EVENT_KIND_STATE
	case job.EventDeliverable:
		return jobpb.JobEventKind_JOB_EVENT_KIND_DELIVERABLE
	case job.EventClosed:
		return jobpb.JobEventKind_JOB_EVENT_KIND_CLOSED
	default:
		return jobpb.JobEventKind_JOB_EVENT_KIND_UNSPECIFIED
	}
}

// recordResult writes a closed job's result to the session store under
// job.ResultKey. The jobs table is the source of truth and the close already
// stands, so a write that fails is logged at warning and the close is not
// undone: a reader that finds no record reads the job itself.
func (s *jobServer) recordResult(ctx context.Context, tenant string, closed *job.Job) {
	result, err := job.ResultOf(closed)
	if err != nil {
		s.logger.WarnContext(ctx, "job result not recorded", "job_id", closed.ID, "error", err)
		return
	}
	data, err := result.Encode()
	if err != nil {
		s.logger.WarnContext(ctx, "job result not recorded", "job_id", closed.ID, "error", err)
		return
	}
	if _, err := s.sessions.Put(ctx, tenant, job.ResultKey(closed.ID), data, ""); err != nil {
		s.logger.WarnContext(ctx, "job result not written to the session store", "job_id", closed.ID, "error", err)
	}
}
