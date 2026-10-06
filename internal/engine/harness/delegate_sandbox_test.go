// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// recordingLauncher is an AgentSandboxLauncher that records the one call it
// receives and returns a canned outcome.
type recordingLauncher struct {
	calls       int
	gotSpec     sandboxed.AgentLaunchSpec
	gotDispatch sandboxed.AgentDispatch
	outcome     sandboxed.AgentRunResult
	err         error

	forkCalls int
	gotSource string
	gotFork   sandboxed.AgentForkSpec
	forkRun   sandboxed.ForkRun
	forkErr   error
	forkIDs   []string

	followCalls int
	gotFollow   string
	followClass string
}

// ForkSandbox forks once with the first of forkIDs, and runs OnForked.
func (r *recordingLauncher) ForkSandbox(_ context.Context, _, source string, spec sandboxed.AgentForkSpec) (string, error) {
	r.forkCalls++
	r.gotSource, r.gotFork = source, spec
	if r.forkErr != nil {
		return "", r.forkErr
	}
	if len(r.forkIDs) == 0 {
		return "", errors.New("no fork id")
	}
	if spec.OnForked != nil {
		if err := spec.OnForked(sandboxed.ForkResponse{Snapshot: r.forkRun.Snapshot, SandboxIDs: r.forkIDs[:1]}); err != nil {
			return "", fmt.Errorf("on forked: %w", err)
		}
	}
	return r.forkIDs[0], nil
}

// FollowAgent returns the canned outcome for the followed fork.
func (r *recordingLauncher) FollowAgent(_ context.Context, sandboxID, class string, dispatch sandboxed.AgentDispatch) (sandboxed.AgentRunResult, error) {
	r.followCalls++
	r.gotFollow, r.followClass, r.gotDispatch = sandboxID, class, dispatch
	return r.outcome, r.err
}

func (r *recordingLauncher) ForkAgent(_ context.Context, source string, spec sandboxed.AgentForkSpec, dispatches []sandboxed.AgentDispatch) (sandboxed.ForkRun, error) {
	r.forkCalls++
	r.gotSource, r.gotFork = source, spec
	r.gotDispatch = dispatches[0]
	if r.forkErr != nil {
		return sandboxed.ForkRun{}, r.forkErr
	}
	if spec.OnForked != nil {
		if err := spec.OnForked(sandboxed.ForkResponse{Snapshot: r.forkRun.Snapshot, SandboxIDs: r.forkIDs}); err != nil {
			return sandboxed.ForkRun{}, fmt.Errorf("on forked: %w", err)
		}
	}
	return r.forkRun, nil
}

func (r *recordingLauncher) LaunchAgent(_ context.Context, spec sandboxed.AgentLaunchSpec, dispatch sandboxed.AgentDispatch) (sandboxed.AgentRunResult, error) {
	r.calls++
	r.gotSpec, r.gotDispatch = spec, dispatch
	return r.outcome, r.err
}

// stubSpecResolver is the S5 launch-spec seam under test.
type stubSpecResolver struct {
	spec          sandboxed.AgentLaunchSpec
	err           error
	gotLoginShape string
	gotTenant     string
	gotAgent      string
}

func (s *stubSpecResolver) ResolveAgentLaunchSpec(ctx context.Context, req AgentLaunchRequest) (sandboxed.AgentLaunchSpec, error) {
	s.gotTenant, s.gotAgent = auth.TenantStringFromContext(ctx), req.AgentName
	s.gotLoginShape = req.LoginShape
	return s.spec, s.err
}

// fixedKeyProvider is a 32-byte-master KeyProvider for the CG-JWT minter.
type fixedKeyProvider struct{}

func (fixedKeyProvider) GetEncryptionKey(context.Context) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}
func (fixedKeyProvider) Name() string                              { return "test" }
func (fixedKeyProvider) Health(context.Context) types.HealthStatus { return types.HealthStatus{} }
func (fixedKeyProvider) Close() error                              { return nil }

func testMinter(t *testing.T) *capabilitygrant.Minter {
	t.Helper()
	m, err := capabilitygrant.NewMinter(context.Background(), capabilitygrant.Config{
		Issuer:      "gibson-test",
		Audience:    "gibson-harness",
		KeyID:       "k1",
		KeyProvider: fixedKeyProvider{},
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

// untrustedAgentInstances returns one untrusted agent with no grpc_endpoint,
// so the in-process/work-queue path is otherwise reachable and only the
// sandbox route (or the deny) intercepts it.
func untrustedAgentInstances() []component.ComponentInfo {
	return []component.ComponentInfo{{
		Kind:         "agent",
		Name:         "zerocool",
		InstanceID:   "i1",
		ContentTrust: componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
		Attested:     true, // cluster code; the catalog states zerocool untrusted
	}}
}

func newSandboxDelegateHarness(
	launcher AgentSandboxLauncher,
	resolver AgentLaunchSpecResolver,
	q component.WorkQueue,
	instances []component.ComponentInfo,
	minter *capabilitygrant.Minter,
) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		logger:                  slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:                  noop.NewTracerProvider().Tracer("test"),
		metrics:                 &NoOpMetricsRecorder{},
		componentRegistry:       &gateFakeRegistry{tenantInstances: instances},
		workQueue:               q,
		componentAuthorizer:     &recordingAuthorizer{allow: true},
		agentLauncher:           launcher,
		agentLaunchSpecResolver: resolver,
		cgMinter:                minter,
		missionCtx: MissionContext{
			ID:           types.NewID(),
			TenantID:     "zerocool-lab",
			MissionRunID: "run-xyz",
			AgentRunID:   "agentrun-1",
		},
	}
}

// TestDelegateToAgent_UntrustedWithLauncher_Launches is the core acceptance:
// an untrusted agent with a launcher wired is LAUNCHED as an ephemeral sandbox
// (the launcher is called), not denied and not enqueued to the work queue.
func TestDelegateToAgent_UntrustedWithLauncher_Launches(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{SandboxID: "sbx-1", ExitCode: 0, Result: &sandboxed.AgentTerminalResult{Success: true, Output: "done"}}}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{
		Image:        "ghcr.io/zeroroot-ai/zerocool:dev",
		SandboxClass: "agent",
		Egress:       []sandboxed.EgressRule{{Host: "api.example.com", Port: 443}},
		Model:        "claude-test",
	}}
	q := successResultQueue(t)
	h := newSandboxDelegateHarness(launcher, resolver, q, untrustedAgentInstances(), testMinter(t))

	ctx := callerCtx(t, "user-1", "zerocool-lab")
	task := agent.NewTask("probe", "Fetch https://example.com", nil)
	res, err := h.DelegateToAgent(ctx, "zerocool", task)
	if err != nil {
		t.Fatalf("untrusted agent with a launcher must launch, not error: %v", err)
	}

	if launcher.calls != 1 {
		t.Fatalf("launcher calls = %d; want exactly 1 (the agent must be launched)", launcher.calls)
	}
	if q.gotKind != "" {
		t.Fatalf("a launched agent was also enqueued to the work queue (gotKind=%q); it must not be", q.gotKind)
	}
	if res.Status != agent.ResultStatusCompleted {
		t.Errorf("result status = %q; want completed", res.Status)
	}

	// The S5 seam was consulted for this tenant + agent.
	if resolver.gotTenant != "zerocool-lab" || resolver.gotAgent != "zerocool" {
		t.Errorf("resolver got (%q,%q); want (zerocool-lab,zerocool)", resolver.gotTenant, resolver.gotAgent)
	}
	// The grant is per-dispatch (run-scoped) and present, and the egress
	// envelope from the manifest reached the launch.
	if launcher.gotDispatch.Grant == "" {
		t.Error("dispatch carried no CG-JWT; the per-dispatch grant must be minted and injected")
	}
	if launcher.gotDispatch.MissionRunID != "run-xyz" {
		t.Errorf("dispatch mission-run = %q; want run-xyz (per-dispatch scope)", launcher.gotDispatch.MissionRunID)
	}
	if len(launcher.gotSpec.Egress) != 1 {
		t.Errorf("spec egress = %+v; want the tenant envelope carried through", launcher.gotSpec.Egress)
	}
	// The task round-trips into the sandbox as base64 protojson.
	raw, decErr := base64.StdEncoding.DecodeString(launcher.gotDispatch.TaskB64)
	if decErr != nil {
		t.Fatalf("decode TaskB64: %v", decErr)
	}
	var pbTask typespb.Task
	if err := protojson.Unmarshal(raw, &pbTask); err != nil {
		t.Fatalf("unmarshal task: %v", err)
	}
}

// TestDelegateToAgent_UntrustedNoLauncher_Denied is the fail-closed control:
// an untrusted agent with NO launcher wired is denied and
// nothing is enqueued.
func TestDelegateToAgent_UntrustedNoLauncher_Denied(t *testing.T) {
	q := successResultQueue(t)
	h := newSandboxDelegateHarness(nil, nil, q, untrustedAgentInstances(), testMinter(t))

	ctx := callerCtx(t, "user-1", "zerocool-lab")
	_, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil))
	if err == nil {
		t.Fatal("untrusted agent with no launcher must be denied")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
	if !strings.Contains(err.Error(), "no sandboxed dispatch") {
		t.Errorf("error = %v; want the fail-closed no-sandboxed-dispatch message", err)
	}
	if q.gotKind != "" {
		t.Fatalf("denied dispatch still enqueued work (gotKind=%q)", q.gotKind)
	}
}

// TestDelegateToAgent_Trusted_Unchanged is the control that proves the sandbox
// route is scoped to untrusted agents: a trusted (unspecified) agent with a
// launcher wired does NOT launch — it takes the existing work-queue path.
func TestDelegateToAgent_Trusted_Unchanged(t *testing.T) {
	launcher := &recordingLauncher{}
	q := successResultQueue(t)
	h := newSandboxDelegateHarness(launcher, &stubSpecResolver{}, q, remoteAgentInstances(), testMinter(t))

	ctx := callerCtx(t, "user-1", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("trusted agent must dispatch on the unchanged path: %v", err)
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher calls = %d; want 0 (a trusted agent must not be sandboxed)", launcher.calls)
	}
	if q.gotKind != "agent" {
		t.Fatalf("trusted agent did not take the work-queue path (gotKind=%q)", q.gotKind)
	}
}

// TestDelegateToAgent_ResolverError: the launch-spec source failing is a
// fail-closed deny — no sandbox is launched.
func TestDelegateToAgent_ResolverError(t *testing.T) {
	launcher := &recordingLauncher{}
	resolver := &stubSpecResolver{err: errStubResolve}
	h := newSandboxDelegateHarness(launcher, resolver, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	_, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", agent.NewTask("p", "g", nil))
	if err == nil {
		t.Fatal("resolver error must deny the dispatch")
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher called %d times; a resolve failure must not launch", launcher.calls)
	}
}

// TestDelegateToAgent_NilResolver: a launcher wired but no spec source is
// fail-closed — sandboxed dispatch needs the catalog manifest (S5).
func TestDelegateToAgent_NilResolver(t *testing.T) {
	launcher := &recordingLauncher{}
	h := newSandboxDelegateHarness(launcher, nil, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", agent.NewTask("p", "g", nil)); err == nil {
		t.Fatal("a nil launch-spec resolver must deny the dispatch")
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher called %d times; must not launch without a spec", launcher.calls)
	}
}

// TestDelegateToAgent_LaunchError: a sandbox launch failure surfaces as a
// delegation error.
func TestDelegateToAgent_LaunchError(t *testing.T) {
	launcher := &recordingLauncher{err: errStubLaunch}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{Image: "img@sha256:x", SandboxClass: "agent"}}
	h := newSandboxDelegateHarness(launcher, resolver, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", agent.NewTask("p", "g", nil)); err == nil {
		t.Fatal("a launch failure must surface as an error")
	}
}

// TestDelegateToAgent_NonZeroExit: a sandbox that runs but exits non-zero is a
// failed delegation, and the log tail is surfaced.
func TestDelegateToAgent_NonZeroExit(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{SandboxID: "sbx-9", ExitCode: 2, Reason: "Error", LogTail: "boom"}}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{Image: "img@sha256:x", SandboxClass: "agent"}}
	h := newSandboxDelegateHarness(launcher, resolver, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	_, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", agent.NewTask("p", "g", nil))
	if err == nil {
		t.Fatal("a non-zero sandbox exit must be a failed delegation")
	}
}

var (
	errStubResolve = errStr("resolve failed")
	errStubLaunch  = errStr("launch failed")
)

type errStr string

func (e errStr) Error() string { return string(e) }

// TestCapRunTimeout pins how an enrollment cap (gibson#597) bounds a
// dispatch: the cap wins over no bound and over a larger bound, a smaller
// bound stays, and no cap changes nothing.
func TestCapRunTimeout(t *testing.T) {
	cases := []struct{ requested, cap, want time.Duration }{
		{0, 0, 0},
		{10 * time.Minute, 0, 10 * time.Minute},
		{0, 5 * time.Minute, 5 * time.Minute},
		{10 * time.Minute, 5 * time.Minute, 5 * time.Minute},
		{2 * time.Minute, 5 * time.Minute, 2 * time.Minute},
	}
	for _, c := range cases {
		if got := capRunTimeout(c.requested, c.cap); got != c.want {
			t.Errorf("capRunTimeout(%v, %v) = %v, want %v", c.requested, c.cap, got, c.want)
		}
	}
}

// sandboxedDelegation runs one delegation of the agent "zerocool" through a
// launcher that returns the given outcome.
func sandboxedDelegation(t *testing.T, outcome sandboxed.AgentRunResult) (agent.Result, error) {
	t.Helper()
	launcher := &recordingLauncher{outcome: outcome}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{Image: "ghcr.io/zeroroot-ai/zerocool:dev", SandboxClass: "agent"}}
	h := newSandboxDelegateHarness(launcher, resolver, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	return h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", agent.NewTask("probe", "goal", nil))
}

// TestDelegateToAgent_SandboxResultReturnsInOutput proves that the structured
// result of a sandboxed agent returns to the caller in Result.Output
// (gibson#682).
func TestDelegateToAgent_SandboxResultReturnsInOutput(t *testing.T) {
	res, err := sandboxedDelegation(t, sandboxed.AgentRunResult{
		SandboxID: "sbx-1",
		Result: &sandboxed.AgentTerminalResult{
			Success:    true,
			Output:     "two hosts answer on 443",
			FindingIDs: []string{"f-1", "f-2"},
			Metadata:   map[string]any{"finish_reason": "stop"},
		},
	})
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if res.Status != agent.ResultStatusCompleted {
		t.Errorf("status = %q; want completed", res.Status)
	}
	if got := res.Output["output"]; got != "two hosts answer on 443" {
		t.Errorf("Output[output] = %v; want the text of the agent", got)
	}
	ids, _ := res.Output["finding_ids"].([]any)
	if len(ids) != 2 || ids[0] != "f-1" || ids[1] != "f-2" {
		t.Errorf("Output[finding_ids] = %v; want [f-1 f-2]", res.Output["finding_ids"])
	}
	md, _ := res.Output["metadata"].(map[string]any)
	if md["finish_reason"] != "stop" {
		t.Errorf("Output[metadata] = %v; want the metadata of the agent", res.Output["metadata"])
	}
}

// TestDelegateToAgent_SandboxExitWithNoResultIsAnError proves that a sandbox
// that exits 0 and wrote no result line returns a clear error.
func TestDelegateToAgent_SandboxExitWithNoResultIsAnError(t *testing.T) {
	_, err := sandboxedDelegation(t, sandboxed.AgentRunResult{SandboxID: "sbx-1"})
	if err == nil {
		t.Fatal("want an error for a run with no result line")
	}
	if code := gibsonCode(t, err); code != ErrHarnessDelegationFailed {
		t.Errorf("code = %q; want %q", code, ErrHarnessDelegationFailed)
	}
	if !strings.Contains(err.Error(), "wrote no result line") {
		t.Errorf("err = %v; want it to name the missing result line", err)
	}
}

// TestDelegateToAgent_SandboxFailureResultIsAnError proves that a result line
// that reports a failure fails the delegation with the reason of the agent.
func TestDelegateToAgent_SandboxFailureResultIsAnError(t *testing.T) {
	_, err := sandboxedDelegation(t, sandboxed.AgentRunResult{
		SandboxID: "sbx-1",
		Result:    &sandboxed.AgentTerminalResult{Success: false, Output: "the model refused"},
	})
	if err == nil || !strings.Contains(err.Error(), "the model refused") {
		t.Fatalf("err = %v; want the failure reason of the agent", err)
	}
}
