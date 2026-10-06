// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/fork"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// The names of the fork contract (sdk#248) and of the sandbox identity
// (setec#235).
const (
	sandboxIDHeader     = fork.MetadataSandboxID
	reasonForkUnclaimed = fork.ReasonForkUnclaimed
	forkErrorDomain     = fork.ErrorDomain
	claimForkMethod     = harnesspb.HarnessCallbackService_ClaimFork_FullMethodName
)

// SandboxIdentityVerifier checks the identity token of a sandbox with setec
// (SandboxService.VerifySandboxIdentity, setec#235). A fork signs with its
// own key, so its token never verifies as the sandbox of its source.
type SandboxIdentityVerifier interface {
	// VerifySandboxIdentity returns the id "<namespace>/<name>/<uid>" of
	// the sandbox of the tenant that the token names. A token that does
	// not verify returns an error that wraps ErrSandboxIdentityRefused.
	VerifySandboxIdentity(ctx context.Context, tenant, token, audience string) (string, error)
}

// ErrSandboxIdentityRefused is the error of a sandbox identity token that
// does not verify. Any other verifier error means setec cannot answer.
var ErrSandboxIdentityRefused = errors.New("harness: the sandbox identity does not verify")

// WithForkLedger wires the ledger of the forks (ADR-0169, D74).
func WithForkLedger(l ForkLedger) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.forkLedger = l
	}
}

// WithSandboxIdentityVerifier wires the check of the sandbox identity
// (setec#235). With no verifier, each call that needs the verified sandbox
// is refused.
func WithSandboxIdentityVerifier(v SandboxIdentityVerifier) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.sandboxIdentity = v
	}
}

// forkGuard holds what the callback interceptors need to refuse the grant
// of a forked source outside the source sandbox. Its ledger is required:
// CallbackServer.Start refuses to run without one.
type forkGuard struct {
	ledger   ForkLedger
	identity SandboxIdentityVerifier
}

// checkForkGrant refuses the grant of a forked source outside the source
// sandbox (D74, sdk#248). After the first fork of a source, each callback
// with its grant must carry a sandbox identity token that setec verifies as
// the source sandbox. The header x-gibson-sandbox-id is never the proof. A
// fork verifies as itself, so it gets FAILED_PRECONDITION with the reason
// GIBSON_FORK_UNCLAIMED until it claims its own dispatch. Only ClaimFork
// accepts the source grant from a fork, and it checks the identity itself.
// A grant with no fork, or a request with no task grant, passes unchanged.
func checkForkGrant(ctx context.Context, guard *forkGuard, method string, logger *slog.Logger) error {
	if method == claimForkMethod {
		return nil
	}
	claims, ok := TaskGrantClaimsFromContext(ctx)
	if !ok || claims.JTI == "" {
		return nil
	}
	source, forked, err := guard.ledger.ForkedSource(ctx, claims.JTI)
	if err != nil {
		return deny(ctx, logger, method, "fork record unreadable",
			status.Error(codes.Unavailable, "the fork record of this grant cannot be read"))
	}
	if !forked {
		return nil
	}
	caller, err := verifiedSandbox(ctx, guard.identity, claims.Tenant.String())
	if err != nil {
		return deny(ctx, logger, method, "sandbox identity refused", err)
	}
	if caller == source {
		return nil
	}
	st := status.New(codes.FailedPrecondition, "this grant belongs to the source sandbox: a fork must claim its own dispatch")
	if detailed, derr := st.WithDetails(&errdetails.ErrorInfo{Reason: reasonForkUnclaimed, Domain: forkErrorDomain}); derr == nil {
		st = detailed
	}
	return deny(ctx, logger, method, "source grant used outside the source sandbox", st.Err())
}

// verifiedSandbox returns the sandbox id that setec verifies from the
// identity token of the caller. A call with no token, a token that does not
// verify, and a header x-gibson-sandbox-id that names another sandbox than
// the token are refused. The returned error is a gRPC status.
func verifiedSandbox(ctx context.Context, v SandboxIdentityVerifier, tenant string) (string, error) {
	if v == nil {
		return "", status.Error(codes.FailedPrecondition, "this daemon cannot verify a sandbox identity")
	}
	token := firstMetadata(ctx, fork.MetadataSandboxIdentity)
	if token == "" {
		return "", status.Error(codes.Unauthenticated, "this call needs the sandbox identity token of the caller")
	}
	id, err := v.VerifySandboxIdentity(ctx, tenant, token, fork.SandboxIdentityAudience)
	switch {
	case errors.Is(err, ErrSandboxIdentityRefused):
		return "", status.Error(codes.Unauthenticated, "the sandbox identity token does not verify")
	case err != nil:
		return "", status.Error(codes.Unavailable, "the sandbox identity cannot be verified now")
	case id == "":
		return "", status.Error(codes.Unauthenticated, "the sandbox identity names no sandbox")
	}
	if claimed := firstMetadata(ctx, sandboxIDHeader); !namesSandbox(claimed, id) {
		return "", status.Error(codes.PermissionDenied, "the sandbox id header names another sandbox than the identity token")
	}
	return id, nil
}

// namesSandbox reports whether a sandbox id that the caller sent agrees with
// the verified id. The caller sends the hostname of its sandbox or the full
// id. An empty value agrees, because the token is the proof.
func namesSandbox(claimed, verified string) bool {
	return claimed == "" || claimed == verified || claimed == sandboxHostname(verified)
}

// firstMetadata returns the first value of an incoming metadata key, or "".
func firstMetadata(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// ClaimFork serves a fork its own dispatch (D74, sdk#248). The fork calls it
// with the grant of its source and its own sandbox identity token. The fork
// is the sandbox that setec verifies from the token, never the sandbox_id of
// the request: a sandbox_id that names another sandbox is refused. A sandbox
// that is not a fork of that grant gets PERMISSION_DENIED, and a second
// claim of one fork gets ALREADY_EXISTS. A fork whose dispatch is not
// recorded yet waits in the call (awaitForkClaim).
func (s *HarnessCallbackService) ClaimFork(ctx context.Context, req *harnesspb.ClaimForkRequest) (*harnesspb.ClaimForkResponse, error) {
	claims, ok := TaskGrantClaimsFromContext(ctx)
	if !ok || claims.JTI == "" {
		return nil, status.Error(codes.Unauthenticated, "ClaimFork needs the task grant of the source")
	}
	if s.forkLedger == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon has no fork support")
	}
	caller, err := verifiedSandbox(ctx, s.sandboxIdentity, claims.Tenant.String())
	if err != nil {
		return nil, err
	}
	if !namesSandbox(req.GetSandboxId(), caller) {
		return nil, status.Error(codes.PermissionDenied, "the sandbox_id of the request names another sandbox than the identity token")
	}
	d, err := s.awaitForkClaim(ctx, claims.JTI, caller)
	switch {
	case errors.Is(err, ErrNotAFork):
		return nil, status.Error(codes.PermissionDenied, "the sandbox is not a fork of this grant")
	case errors.Is(err, ErrForkClaimed):
		return nil, status.Error(codes.AlreadyExists, "the fork was already claimed")
	case errors.Is(err, ErrForkPending):
		return nil, status.Error(codes.DeadlineExceeded, "the dispatch of this fork was not recorded in time")
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

// forkClaimWait bounds how long ClaimFork waits for the dispatch of a
// pending fork, and forkClaimPoll is how often it looks. A fork of a caller
// (gibson#803) waits until the first node of the child mission is
// dispatched, so the bound is the park bound of the sdk.
var (
	forkClaimWait = fork.DefaultParkTimeout
	forkClaimPoll = 250 * time.Millisecond
)

// awaitForkClaim claims the dispatch of a fork. While the dispatch is not
// recorded it waits, until forkClaimWait or the end of ctx, so the fork
// parks in the call and not in a retry loop of its own.
func (s *HarnessCallbackService) awaitForkClaim(ctx context.Context, jti, sandboxID string) (ForkDispatch, error) {
	deadline := time.NewTimer(forkClaimWait)
	defer deadline.Stop()
	for {
		d, err := s.forkLedger.Claim(ctx, jti, sandboxID)
		if err == nil {
			return d, nil
		}
		if !errors.Is(err, ErrForkPending) {
			return ForkDispatch{}, fmt.Errorf("claim fork %s: %w", sandboxID, err)
		}
		select {
		case <-ctx.Done():
			return ForkDispatch{}, ErrForkPending
		case <-deadline.C:
			return ForkDispatch{}, ErrForkPending
		case <-time.After(forkClaimPoll):
		}
	}
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
