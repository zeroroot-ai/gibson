// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The names of the fork contract (sdk#248). They match the sdk package fork.
const (
	sandboxIDHeader     = "x-gibson-sandbox-id"
	reasonForkUnclaimed = "GIBSON_FORK_UNCLAIMED"
	forkErrorDomain     = "gibson.harness.v1"
	claimForkMethod     = "/gibson.harness.v1.HarnessCallbackService/ClaimFork"
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
