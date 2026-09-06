// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
)

// DevboxExec — run a command inside the caller's session sandbox (gibson#1183).
//
// The per-call SANDBOXED path launches a microVM, runs one command and
// destroys it. That is right for a tool invocation and useless for a coding
// agent: `git clone` then `go build` must see the same filesystem. DevboxExec
// routes into the session sandbox pinned to (tenant, session_id), launching it
// on first use, so /workspace persists across commands.
//
// TENANCY. The tenant half of the session key is derived server-side from the
// authenticated caller (sessionCallerTenant), exactly as the session-context
// RPCs do. No field on the wire carries a tenant, so naming another tenant's
// session is unrepresentable rather than rejected — and the key is
// length-prefixed so it cannot be forged by embedding a separator in the
// agent-chosen session_id.
//
// ISOLATION. argv is executed directly inside the microVM; no shell is
// interposed, so nothing here quotes, globs or redirects. Arbitrary argv is
// the product — this is a devbox for a coding agent — and per ADR-0052 the
// microVM is the containment boundary: a sandbox escape is a setec defect, not
// a gibson one. What gibson owns is that the command lands in the RIGHT
// sandbox, which is what the tenant-derived key above is for.
//
// STREAM CONTRACT. stdout and stderr arrive interleaved in arrival order and
// are never merged. Exactly one terminal message is sent: an exit, or an
// error. A stream that ends without one is a bug, because "the command
// succeeded" and "the connection dropped" must never look alike to the caller
// — which is why the exit path below distinguishes setec's exec status rather
// than forwarding a bare code.
const maxDevboxArgv = 4096

// DevboxExec implements harnesspb.HarnessCallbackServiceServer.
func (s *HarnessCallbackService) DevboxExec(
	req *harnesspb.DevboxExecRequest,
	stream harnesspb.HarnessCallbackService_DevboxExecServer,
) error {
	const rpc = "DevboxExec"
	ctx := stream.Context()

	if s.sessionSandboxes == nil {
		return status.Error(codes.Unavailable,
			rpc+": session sandboxes are not wired on this daemon")
	}

	tenant, err := s.sessionCallerTenant(ctx, rpc)
	if err != nil {
		return err
	}
	if err := validateSessionID(rpc, req.GetSessionId()); err != nil {
		return err
	}
	argv := req.GetArgv()
	if len(argv) == 0 {
		return status.Error(codes.InvalidArgument, rpc+": argv is required")
	}
	if len(argv) > maxDevboxArgv {
		return status.Errorf(codes.InvalidArgument,
			"%s: argv has %d entries, limit is %d", rpc, len(argv), maxDevboxArgv)
	}
	// An empty argv[0] cannot name a binary; catching it here turns a confusing
	// runtime failure inside the VM into a clear rejection.
	if argv[0] == "" {
		return status.Error(codes.InvalidArgument, rpc+": argv[0] must name a binary")
	}

	execStream, err := s.sessionSandboxes.Exec(ctx, tenant, req.GetSessionId(), argv)
	if err != nil {
		if errors.Is(err, sandboxed.ErrSessionUnavailable) {
			return status.Error(codes.Unavailable, rpc+": "+err.Error())
		}
		s.logger.ErrorContext(ctx, "devbox exec: could not start command",
			slog.String("rpc", rpc), slog.String("error", err.Error()))
		// The message is deliberately generic: it is produced by resolving a
		// session sandbox, and the underlying error can carry cluster detail
		// the calling component has no business seeing.
		return status.Error(codes.Internal, rpc+": could not start the command in the session sandbox")
	}
	defer func() { _ = execStream.Close() }()

	// stdin is delivered whole and then closed. The wire request carries a
	// single bytes field rather than a stream, so there is nothing to pump:
	// a command that reads to EOF would hang forever without the CloseSend.
	if stdin := req.GetStdin(); len(stdin) > 0 {
		if err := execStream.Send(stdin); err != nil {
			return status.Errorf(codes.Internal, "%s: writing stdin: %v", rpc, err)
		}
	}
	if err := execStream.CloseSend(); err != nil {
		return status.Errorf(codes.Internal, "%s: closing stdin: %v", rpc, err)
	}

	return s.pumpDevboxExec(ctx, rpc, execStream, stream)
}

// pumpDevboxExec forwards output until the terminal event, and guarantees the
// caller sees exactly one terminal message.
func (s *HarnessCallbackService) pumpDevboxExec(
	ctx context.Context,
	rpc string,
	from sandboxed.ExecStream,
	to harnesspb.HarnessCallbackService_DevboxExecServer,
) error {
	for {
		// A cancelled caller stops the pump; the deferred Close tears the
		// upstream exec down rather than leaving it writing into a dead stream.
		if err := ctx.Err(); err != nil {
			//nolint:wrapcheck // already a gRPC status; wrapping hides the code from status.Code()
			return status.FromContextError(err).Err()
		}

		ev, err := from.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Terminal-without-exit. Reporting this as success would let a
				// vanished microVM read as a clean run — the exact confusion
				// setec's exit Status exists to prevent.
				return status.Error(codes.Internal,
					rpc+": the command stream ended without an exit status; the outcome is unknown")
			}
			return status.Errorf(codes.Internal, "%s: reading command output: %v", rpc, err)
		}

		switch {
		case ev.Exit != nil:
			return s.sendDevboxExit(rpc, ev.Exit, to)

		case len(ev.Stdout) > 0:
			if err := to.Send(&harnesspb.DevboxExecResponse{
				Payload: &harnesspb.DevboxExecResponse_Stdout{Stdout: ev.Stdout},
			}); err != nil {
				return fmt.Errorf("%s: forwarding stdout: %w", rpc, err)
			}

		case len(ev.Stderr) > 0:
			if err := to.Send(&harnesspb.DevboxExecResponse{
				Payload: &harnesspb.DevboxExecResponse_Stderr{Stderr: ev.Stderr},
			}); err != nil {
				return fmt.Errorf("%s: forwarding stderr: %w", rpc, err)
			}
		}
	}
}

// sendDevboxExit maps setec's exec status onto the wire's terminal message.
//
// Only ExecExited carries a meaningful code. The other two mean the command
// did NOT run to completion, and forwarding a zero there would report success
// for a build that never happened — so they become an error payload instead.
func (s *HarnessCallbackService) sendDevboxExit(
	rpc string,
	exit *sandboxed.ExecExit,
	to harnesspb.HarnessCallbackService_DevboxExecServer,
) error {
	if exit.Status == sandboxed.ExecExited {
		if err := to.Send(&harnesspb.DevboxExecResponse{
			Payload: &harnesspb.DevboxExecResponse_Exit{
				Exit: &harnesspb.DevboxExecExit{ExitCode: exit.Code},
			},
		}); err != nil {
			return fmt.Errorf("%s: sending exit: %w", rpc, err)
		}
		return nil
	}

	msg := exit.Message
	if msg == "" {
		msg = "the command did not run to completion and no exit code is available"
	}
	if err := to.Send(&harnesspb.DevboxExecResponse{
		Payload: &harnesspb.DevboxExecResponse_Error{
			Error: &harnesspb.HarnessError{
				Message: rpc + ": " + msg,
			},
		},
	}); err != nil {
		return fmt.Errorf("%s: sending error verdict: %w", rpc, err)
	}
	return nil
}
