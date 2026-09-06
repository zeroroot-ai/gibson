// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
)

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

// devboxStream captures what the handler sent to the component.
type devboxStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*harnesspb.DevboxExecResponse
}

func (s *devboxStream) Context() context.Context { return s.ctx }
func (s *devboxStream) Send(m *harnesspb.DevboxExecResponse) error {
	s.sent = append(s.sent, m)
	return nil
}

// scriptedExec replays a fixed sequence of events, then the recorded error.
type scriptedExec struct {
	events []sandboxed.ExecEvent
	final  error // returned once events are exhausted
	i      int

	stdin      []byte
	closedSend bool
	closed     bool
}

func (s *scriptedExec) Send(b []byte) error { s.stdin = append(s.stdin, b...); return nil }
func (s *scriptedExec) CloseSend() error    { s.closedSend = true; return nil }
func (s *scriptedExec) Close() error        { s.closed = true; return nil }
func (s *scriptedExec) Recv() (sandboxed.ExecEvent, error) {
	if s.i < len(s.events) {
		e := s.events[s.i]
		s.i++
		return e, nil
	}
	if s.final != nil {
		return sandboxed.ExecEvent{}, s.final
	}
	return sandboxed.ExecEvent{}, io.EOF
}

// scriptedSessionClient hands out one scripted exec stream.
type scriptedSessionClient struct {
	sandboxed.SandboxClient
	stream    *scriptedExec
	launchErr error
	gotArgv   []string
}

func (c *scriptedSessionClient) LaunchSession(context.Context, sandboxed.SessionLaunchRequest) (sandboxed.LaunchResponse, error) {
	if c.launchErr != nil {
		return sandboxed.LaunchResponse{}, c.launchErr
	}
	return sandboxed.LaunchResponse{SandboxID: "ns/sb/uid"}, nil
}

func (c *scriptedSessionClient) Exec(_ context.Context, _ string, argv []string) (sandboxed.ExecStream, error) {
	c.gotArgv = argv
	return c.stream, nil
}

func (c *scriptedSessionClient) Kill(context.Context, string) error { return nil }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func devboxService(t *testing.T, client sandboxed.SessionClient) *HarnessCallbackService {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	opts := []CallbackServiceOption{}
	if client != nil {
		opts = append(opts, WithSessionSandboxes(
			sandboxed.NewSessionRegistry(client, sandboxed.SessionSpec{
				Image: "devbox:latest", VCPU: 2, Memory: "4Gi",
				SandboxClass: "devbox", Idle: 3600_000_000_000,
			})))
	}
	return NewHarnessCallbackService(logger, opts...)
}

func tenantCtx(t *testing.T) context.Context {
	t.Helper()
	return auth.ContextWithTenantString(context.Background(), "tenant-a")
}

func newDevboxStream(ctx context.Context) *devboxStream {
	return &devboxStream{ctx: ctx}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// An unwired daemon must say so, not silently run the command elsewhere.
func TestDevboxExec_UnavailableWithoutRegistry(t *testing.T) {
	svc := devboxService(t, nil)
	err := svc.DevboxExec(
		&harnesspb.DevboxExecRequest{SessionId: "s", Argv: []string{"true"}},
		newDevboxStream(tenantCtx(t)),
	)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// No tenant in the caller identity means no session namespace to operate in.
// Fail closed, exactly as the session-context RPCs do.
func TestDevboxExec_DeniedWithoutTenant(t *testing.T) {
	svc := devboxService(t, &scriptedSessionClient{stream: &scriptedExec{}})
	err := svc.DevboxExec(
		&harnesspb.DevboxExecRequest{SessionId: "s", Argv: []string{"true"}},
		newDevboxStream(context.Background()), // no tenant
	)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDevboxExec_RejectsBadRequests(t *testing.T) {
	cases := []struct {
		name string
		req  *harnesspb.DevboxExecRequest
	}{
		{"no session id", &harnesspb.DevboxExecRequest{Argv: []string{"true"}}},
		{"no argv", &harnesspb.DevboxExecRequest{SessionId: "s"}},
		{"empty argv[0]", &harnesspb.DevboxExecRequest{SessionId: "s", Argv: []string{""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := devboxService(t, &scriptedSessionClient{stream: &scriptedExec{}})
			err := svc.DevboxExec(tc.req, newDevboxStream(tenantCtx(t)))
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// The happy path: output is forwarded in order, streams stay separated, and
// the exit code is the command's own.
func TestDevboxExec_ForwardsOutputThenExit(t *testing.T) {
	sc := &scriptedSessionClient{stream: &scriptedExec{
		events: []sandboxed.ExecEvent{
			{Stdout: []byte("building\n")},
			{Stderr: []byte("warning\n")},
			{Stdout: []byte("done\n")},
			{Exit: &sandboxed.ExecExit{Status: sandboxed.ExecExited, Code: 7}},
		},
	}}
	svc := devboxService(t, sc)
	st := newDevboxStream(tenantCtx(t))

	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"go", "build"}, Stdin: []byte("in"),
	}, st)
	require.NoError(t, err)

	require.Len(t, st.sent, 4)
	assert.Equal(t, []byte("building\n"), st.sent[0].GetStdout())
	assert.Equal(t, []byte("warning\n"), st.sent[1].GetStderr())
	assert.Equal(t, []byte("done\n"), st.sent[2].GetStdout())
	require.NotNil(t, st.sent[3].GetExit())
	assert.Equal(t, int32(7), st.sent[3].GetExit().GetExitCode())

	assert.Equal(t, []string{"go", "build"}, sc.gotArgv, "argv must reach setec unchanged")
	assert.Equal(t, []byte("in"), sc.stream.stdin)
	assert.True(t, sc.stream.closedSend, "stdin must be closed or a reader hangs forever")
	assert.True(t, sc.stream.closed, "the exec stream must be released")
}

// THE IMPORTANT ONE. A stream that ends without an exit must NOT read as
// success — that is a vanished microVM being reported as a clean build.
func TestDevboxExec_StreamEndingWithoutExitIsNotSuccess(t *testing.T) {
	sc := &scriptedSessionClient{stream: &scriptedExec{
		events: []sandboxed.ExecEvent{{Stdout: []byte("partial output\n")}},
		final:  io.EOF,
	}}
	svc := devboxService(t, sc)
	st := newDevboxStream(tenantCtx(t))

	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"go", "build"},
	}, st)

	require.Error(t, err, "a stream with no exit event must be an error, never a silent success")
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "without an exit status")
	for _, m := range st.sent {
		assert.Nil(t, m.GetExit(), "no exit may be synthesised when none was received")
	}
}

// A non-EXITED verdict has no meaningful code. Forwarding a zero there would
// report success for a command that never completed.
func TestDevboxExec_FailedVerdictIsAnErrorNotExitZero(t *testing.T) {
	sc := &scriptedSessionClient{stream: &scriptedExec{
		events: []sandboxed.ExecEvent{
			{Exit: &sandboxed.ExecExit{Status: sandboxed.ExecFailed, Message: "sandbox evicted"}},
		},
	}}
	svc := devboxService(t, sc)
	st := newDevboxStream(tenantCtx(t))

	require.NoError(t, svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"go", "test"},
	}, st))

	require.Len(t, st.sent, 1)
	assert.Nil(t, st.sent[0].GetExit(), "a failed verdict must not become an exit code")
	require.NotNil(t, st.sent[0].GetError())
	assert.Contains(t, st.sent[0].GetError().GetMessage(), "sandbox evicted")
}

func TestDevboxExec_UnknownVerdictIsAnError(t *testing.T) {
	sc := &scriptedSessionClient{stream: &scriptedExec{
		events: []sandboxed.ExecEvent{
			{Exit: &sandboxed.ExecExit{Status: sandboxed.ExecUnknown}},
		},
	}}
	svc := devboxService(t, sc)
	st := newDevboxStream(tenantCtx(t))

	require.NoError(t, svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"true"},
	}, st))
	require.Len(t, st.sent, 1)
	assert.Nil(t, st.sent[0].GetExit())
	require.NotNil(t, st.sent[0].GetError())
}

// A launch failure must not leak cluster detail to the calling component.
func TestDevboxExec_LaunchFailureIsGeneric(t *testing.T) {
	sc := &scriptedSessionClient{
		stream:    &scriptedExec{},
		launchErr: errors.New("node ip-10-40-121-135 has no capacity in cluster zeroroot-ai-prod"),
	}
	svc := devboxService(t, sc)
	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"true"},
	}, newDevboxStream(tenantCtx(t)))

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.NotContains(t, err.Error(), "ip-10-40-121-135")
	assert.NotContains(t, err.Error(), "zeroroot-ai-prod")
}

// ---------------------------------------------------------------------------
// error paths — each of these is a way the command can fail to run, and every
// one of them must be distinguishable from "it ran and succeeded"
// ---------------------------------------------------------------------------

// failingStream fails at a chosen point in the exchange.
type failingStream struct {
	scriptedExec
	sendErr      error
	closeSendErr error
	recvErr      error
}

func (s *failingStream) Send(b []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	return s.scriptedExec.Send(b)
}
func (s *failingStream) CloseSend() error {
	if s.closeSendErr != nil {
		return s.closeSendErr
	}
	return s.scriptedExec.CloseSend()
}
func (s *failingStream) Recv() (sandboxed.ExecEvent, error) {
	if s.recvErr != nil {
		return sandboxed.ExecEvent{}, s.recvErr
	}
	return s.scriptedExec.Recv()
}

// failingClient hands out a stream that is not a *scriptedExec.
type failingClient struct {
	sandboxed.SandboxClient
	stream sandboxed.ExecStream
}

func (c *failingClient) LaunchSession(context.Context, sandboxed.SessionLaunchRequest) (sandboxed.LaunchResponse, error) {
	return sandboxed.LaunchResponse{SandboxID: "ns/sb/uid"}, nil
}
func (c *failingClient) Exec(context.Context, string, []string) (sandboxed.ExecStream, error) {
	return c.stream, nil
}
func (c *failingClient) Kill(context.Context, string) error { return nil }

func TestDevboxExec_RejectsOversizedArgv(t *testing.T) {
	argv := make([]string, maxDevboxArgv+1)
	for i := range argv {
		argv[i] = "x"
	}
	svc := devboxService(t, &scriptedSessionClient{stream: &scriptedExec{}})
	err := svc.DevboxExec(
		&harnesspb.DevboxExecRequest{SessionId: "s", Argv: argv},
		newDevboxStream(tenantCtx(t)),
	)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "limit is")
}

// stdin that cannot be written means the command runs against the wrong input.
// Fail rather than run it anyway.
func TestDevboxExec_StdinWriteFailureIsReported(t *testing.T) {
	svc := devboxService(t, &failingClient{stream: &failingStream{sendErr: errors.New("pipe closed")}})
	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"cat"}, Stdin: []byte("data"),
	}, newDevboxStream(tenantCtx(t)))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "writing stdin")
}

// A stdin that is never closed hangs any command that reads to EOF, so a
// failure to close must surface rather than leave the caller waiting.
func TestDevboxExec_StdinCloseFailureIsReported(t *testing.T) {
	svc := devboxService(t, &failingClient{stream: &failingStream{closeSendErr: errors.New("broken")}})
	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"cat"},
	}, newDevboxStream(tenantCtx(t)))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "closing stdin")
}

// A transport error mid-read is not EOF and must not be reported as the
// "ended without exit" case — the two have different causes.
func TestDevboxExec_ReadFailureIsReported(t *testing.T) {
	svc := devboxService(t, &failingClient{stream: &failingStream{recvErr: errors.New("connection reset")}})
	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"true"},
	}, newDevboxStream(tenantCtx(t)))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "reading command output")
	assert.NotContains(t, err.Error(), "without an exit status")
}

// A caller that hangs up stops the pump; the exit code of a command nobody is
// listening to is not worth blocking on.
func TestDevboxExec_CancelledCallerStopsThePump(t *testing.T) {
	ctx, cancel := context.WithCancel(tenantCtx(t))
	cancel()
	svc := devboxService(t, &scriptedSessionClient{stream: &scriptedExec{
		events: []sandboxed.ExecEvent{{Stdout: []byte("x")}},
	}})
	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"true"},
	}, newDevboxStream(ctx))
	require.Error(t, err)
	assert.Equal(t, codes.Canceled, status.Code(err))
}

// A failed verdict with no message still has to say something useful.
func TestDevboxExec_FailedVerdictWithoutMessageStillExplains(t *testing.T) {
	svc := devboxService(t, &scriptedSessionClient{stream: &scriptedExec{
		events: []sandboxed.ExecEvent{{Exit: &sandboxed.ExecExit{Status: sandboxed.ExecFailed}}},
	}})
	st := newDevboxStream(tenantCtx(t))
	require.NoError(t, svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: "s", Argv: []string{"true"},
	}, st))
	require.Len(t, st.sent, 1)
	require.NotNil(t, st.sent[0].GetError())
	assert.Contains(t, st.sent[0].GetError().GetMessage(), "did not run to completion")
}

// An over-long session id is a storage key, not content — bound it.
func TestDevboxExec_RejectsOversizedSessionID(t *testing.T) {
	long := make([]byte, maxSessionIDBytes+1)
	for i := range long {
		long[i] = 'a'
	}
	svc := devboxService(t, &scriptedSessionClient{stream: &scriptedExec{}})
	err := svc.DevboxExec(&harnesspb.DevboxExecRequest{
		SessionId: string(long), Argv: []string{"true"},
	}, newDevboxStream(tenantCtx(t)))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
