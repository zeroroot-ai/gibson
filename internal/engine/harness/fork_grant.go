// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/fork"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// The names of the fork contract (sdk#248).
const (
	sandboxIDHeader     = fork.MetadataSandboxID
	reasonForkUnclaimed = fork.ReasonForkUnclaimed
	forkErrorDomain     = fork.ErrorDomain
	claimForkMethod     = harnesspb.HarnessCallbackService_ClaimFork_FullMethodName
)

// WithForkLedger wires the ledger of the forks (ADR-0169, D74).
func WithForkLedger(l ForkLedger) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.forkLedger = l
	}
}

// checkForkGrant refuses the grant of a forked source outside the source
// sandbox (D74, sdk#248). After the first fork of a source, each callback
// with its grant must carry the sandbox id of the source. A fork carries its
// own id, so it gets FAILED_PRECONDITION with the reason
// GIBSON_FORK_UNCLAIMED until it claims its own dispatch. Only ClaimFork
// accepts the source grant from a fork. A grant with no fork, or a request
// with no task grant, passes unchanged.
func checkForkGrant(ctx context.Context, forks ForkLedger, method string, logger *slog.Logger) error {
	if forks == nil || method == claimForkMethod {
		return nil
	}
	claims, ok := TaskGrantClaimsFromContext(ctx)
	if !ok || claims.JTI == "" {
		return nil
	}
	source, forked, err := forks.ForkedSource(ctx, claims.JTI)
	if err != nil {
		return deny(ctx, logger, method, "fork record unreadable",
			status.Error(codes.Unavailable, "the fork record of this grant cannot be read"))
	}
	if !forked || callerSandbox(ctx) == sandboxHostname(source) {
		return nil
	}
	st := status.New(codes.FailedPrecondition, "this grant belongs to the source sandbox: a fork must claim its own dispatch")
	if detailed, derr := st.WithDetails(&errdetails.ErrorInfo{Reason: reasonForkUnclaimed, Domain: forkErrorDomain}); derr == nil {
		st = detailed
	}
	return deny(ctx, logger, method, "source grant used outside the source sandbox", st.Err())
}

// callerSandbox returns the sandbox id that the caller sent, or "".
func callerSandbox(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get(sandboxIDHeader); len(v) > 0 {
		return v[0]
	}
	return ""
}

// ClaimFork serves a fork its own dispatch (D74, sdk#248). The fork calls it
// with the grant of its source, and from then on uses the grant of the
// dispatch. A sandbox that is not a fork of that grant gets
// PERMISSION_DENIED, and a second claim of one fork gets ALREADY_EXISTS.
func (s *HarnessCallbackService) ClaimFork(ctx context.Context, req *harnesspb.ClaimForkRequest) (*harnesspb.ClaimForkResponse, error) {
	claims, ok := TaskGrantClaimsFromContext(ctx)
	if !ok || claims.JTI == "" {
		return nil, status.Error(codes.Unauthenticated, "ClaimFork needs the task grant of the source")
	}
	if s.forkLedger == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon has no fork support")
	}
	d, err := s.forkLedger.Claim(ctx, claims.JTI, req.GetSandboxId())
	switch {
	case errors.Is(err, ErrNotAFork):
		return nil, status.Error(codes.PermissionDenied, "the sandbox is not a fork of this grant")
	case errors.Is(err, ErrForkClaimed):
		return nil, status.Error(codes.AlreadyExists, "the fork was already claimed")
	case errors.Is(err, ErrForkPending):
		return nil, status.Error(codes.Unavailable, "the forks of this grant are not recorded yet; retry")
	case err != nil:
		s.logger.Error("ClaimFork: fork ledger failed", "error", err)
		return nil, status.Error(codes.Unavailable, "the fork record cannot be read")
	}
	task, err := forkTask(d.TaskB64)
	if err != nil {
		return nil, status.Error(codes.Internal, "the task of the fork cannot be decoded")
	}
	return &harnesspb.ClaimForkResponse{
		Grant:        d.Grant,
		MissionId:    d.MissionID,
		MissionRunId: d.MissionRunID,
		AgentRunId:   d.AgentRunID,
		NodeId:       d.NodeID,
		Model:        d.Model,
		Task:         task,
	}, nil
}

// forkTask decodes the base64 protojson task of a fork dispatch.
func forkTask(b64 string) (*typespb.Task, error) {
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode fork task: %w", err)
	}
	t := &typespb.Task{}
	if err := protojson.Unmarshal(raw, t); err != nil {
		return nil, fmt.Errorf("decode fork task: %w", err)
	}
	return t, nil
}
