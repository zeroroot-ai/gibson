// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

// Package daemon — session-sandbox half of the Setec client adapter
// (gibson#1183).
//
// Same contract as sandboxed_setec_adapter.go: this file is the single point
// of contact between gibson and setec's generated client for SESSION
// sandboxes. The sandboxed package stays free of setec imports.
//
// Build tag `setec_integration` matches the rest of the adapter, so gibson
// still compiles where the setec module is unavailable.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

// Compile-time proof that the adapter satisfies the session surface. Without
// this the daemon would only discover a missing method when wiring runs.
var _ sandboxed.SessionClient = (*setecClient)(nil)

// NewSetecSessionClient dials setec and returns the session surface, or
// (nil, nil) when the sandbox subsystem is disabled — the same
// unconditionally-callable shape as NewSetecSandboxClient, so the daemon needs
// no build-tag branch.
func NewSetecSessionClient(cfg config.SandboxConfig) (sandboxed.SessionClient, error) {
	c, err := NewSetecSandboxClient(cfg)
	if err != nil || c == nil {
		return nil, err
	}
	sc, ok := c.(sandboxed.SessionClient)
	if !ok {
		// Unreachable while the var _ assertion above compiles, but a type
		// assertion that can silently yield nil is how a feature ships dead.
		return nil, errors.New("setec: client does not implement the session surface")
	}
	return sc, nil
}

// LaunchSession creates a session-mode sandbox with a durable /workspace.
//
// Nothing runs at launch: setec requires a command, so the sandbox is parked
// on a keepalive and every real command arrives later over Exec. That is the
// whole point — the workspace outlives any one command.
func (c *setecClient) LaunchSession(ctx context.Context, req sandboxed.SessionLaunchRequest) (sandboxed.LaunchResponse, error) {
	// Isolation posture (ADR-0052), same rule as the per-call path: gibson
	// names the class rather than deferring to the cluster default, so an
	// install missing the class fails the launch instead of quietly
	// downgrading the isolation a session runs under.
	if req.SandboxClass == "" {
		return sandboxed.LaunchResponse{},
			errors.New("setec: refusing to launch a session without a sandbox class")
	}

	env := req.Env
	if c.masterKEK != nil && !c.tenantID.IsZero() {
		wrapped, err := wrapSecretEnvVars(c.masterKEK, c.tenantID, req.Env)
		if err != nil {
			return sandboxed.LaunchResponse{},
				fmt.Errorf("setec: KEK envelope-wrap failed: %w", err)
		}
		env = wrapped
	}

	lifecycle := &setecv1.Lifecycle{
		Mode:      "session",
		Workspace: &setecv1.Workspace{Size: req.WorkspaceSize},
	}
	// The idle bound is the backstop against a forgotten session pinning a PVC
	// and a metal node forever. Leaving it unset would make a leaked session
	// permanent, so an absent value is a caller bug rather than "no limit".
	if req.Idle <= 0 {
		return sandboxed.LaunchResponse{},
			errors.New("setec: refusing to launch a session with no idle bound")
	}
	lifecycle.Timeout = req.Idle.String()

	resp, err := c.inner.Launch(ctx, &setecv1.LaunchRequest{
		SandboxClass: req.SandboxClass,
		Image:        req.Image,
		// setec requires a command. A session's PID 1 exists only to keep the
		// microVM alive; the agent's commands arrive over Exec and each gets
		// its own process. `sleep infinity` is the smallest thing that does
		// that without pulling in a shell loop.
		Command: []string{"sleep", "infinity"},
		Env:     env,
		Resources: &setecv1.Resources{
			Vcpu:   uint32(req.VCPU),
			Memory: req.Memory,
		},
		Lifecycle: lifecycle,
	})
	if err != nil {
		return sandboxed.LaunchResponse{}, err
	}
	return sandboxed.LaunchResponse{SandboxID: resp.GetSandboxId()}, nil
}

// Exec opens a command stream inside an existing session sandbox.
//
// setec's Exec is bidirectional; the start message must be first and exactly
// once. This sends it eagerly so a caller that never writes stdin still gets
// the command running.
func (c *setecClient) Exec(ctx context.Context, sandboxID string, argv []string) (sandboxed.ExecStream, error) {
	if sandboxID == "" {
		return nil, errors.New("setec: exec needs a sandbox id")
	}
	if len(argv) == 0 {
		return nil, errors.New("setec: exec needs a command")
	}

	stream, err := c.inner.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("setec: opening exec stream: %w", err)
	}
	if err := stream.Send(&setecv1.SandboxServiceExecRequest{
		Request: &setecv1.SandboxServiceExecRequest_Start{
			Start: &setecv1.SessionExecStart{
				SandboxId: sandboxID,
				Command:   argv,
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("setec: starting exec: %w", err)
	}
	return &setecExecStream{stream: stream}, nil
}

// setecExecStream adapts setec's bidi stream to sandboxed.ExecStream.
type setecExecStream struct {
	stream setecv1.SandboxService_ExecClient

	// closeOnce makes Close idempotent — the handler defers it and may also
	// hit an error path that closes early.
	closeOnce sync.Once
	sentEOF   bool
}

func (s *setecExecStream) Send(stdin []byte) error {
	if s.sentEOF {
		// setec answers INVALID_ARGUMENT for stdin-after-eof. Failing here
		// names the actual mistake instead of surfacing a transport error.
		return errors.New("setec: stdin sent after stdin_eof")
	}
	return s.stream.Send(&setecv1.SandboxServiceExecRequest{
		Request: &setecv1.SandboxServiceExecRequest_Stdin{Stdin: stdin},
	})
}

func (s *setecExecStream) CloseSend() error {
	if s.sentEOF {
		return nil
	}
	s.sentEOF = true
	// Half-close at the protocol level first: a command reading to EOF hangs
	// forever without it, and gRPC's CloseSend alone does not convey it.
	if err := s.stream.Send(&setecv1.SandboxServiceExecRequest{
		Request: &setecv1.SandboxServiceExecRequest_StdinEof{StdinEof: true},
	}); err != nil {
		return err
	}
	return s.stream.CloseSend()
}

func (s *setecExecStream) Recv() (sandboxed.ExecEvent, error) {
	msg, err := s.stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			// Surface EOF unwrapped so the handler's errors.Is check sees it;
			// it turns this into "outcome unknown" rather than success.
			return sandboxed.ExecEvent{}, io.EOF
		}
		return sandboxed.ExecEvent{}, err
	}

	switch r := msg.GetResponse().(type) {
	case *setecv1.SandboxServiceExecResponse_Output:
		out := r.Output
		if out.GetStream() == "stderr" {
			return sandboxed.ExecEvent{Stderr: out.GetData()}, nil
		}
		return sandboxed.ExecEvent{Stdout: out.GetData()}, nil

	case *setecv1.SandboxServiceExecResponse_Exit:
		return sandboxed.ExecEvent{Exit: mapSetecExit(r.Exit)}, nil

	default:
		// An unrecognised payload must not be dropped silently — a future
		// setec adds a variant and this adapter would otherwise treat a
		// terminal event as "nothing happened" and spin.
		return sandboxed.ExecEvent{}, fmt.Errorf("setec: unrecognised exec response %T", r)
	}
}

func (s *setecExecStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if !s.sentEOF {
			s.sentEOF = true
			err = s.stream.CloseSend()
		}
	})
	return err
}

// mapSetecExit translates setec's exit verdict, preserving the distinction
// between "ran and produced this code" and every way an exec ends WITHOUT
// one. Flattening those would let a vanished microVM read as a clean success.
func mapSetecExit(e *setecv1.SessionExecExit) *sandboxed.ExecExit {
	if e == nil {
		return &sandboxed.ExecExit{
			Status:  sandboxed.ExecUnknown,
			Message: "setec sent an empty exit message",
		}
	}
	switch e.GetStatus() {
	case setecv1.SessionExecExit_STATUS_EXITED:
		return &sandboxed.ExecExit{Status: sandboxed.ExecExited, Code: e.GetExitCode()}
	case setecv1.SessionExecExit_STATUS_UNSPECIFIED:
		// Documented by setec as never sent: its presence means the message
		// did not come from a setec frontend, or was zero-valued in transit.
		return &sandboxed.ExecExit{
			Status:  sandboxed.ExecUnknown,
			Message: "exit status unspecified; the outcome is unknown",
		}
	default:
		msg := e.GetMessage()
		if msg == "" {
			msg = e.GetStatus().String()
		}
		return &sandboxed.ExecExit{Status: sandboxed.ExecFailed, Message: msg}
	}
}
