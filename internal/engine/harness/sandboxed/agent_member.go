// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// memberLifetime is how long one member sandbox may live before setec reaps
// it. A member is always-on, but a sandbox with no bound is a sandbox nothing
// ever reaps when the daemon that launched it is gone. A reaped member stops
// reporting, the reconciler marks it dead, and a replacement is launched, so
// the bound costs one relaunch a day and buys a hard ceiling on every leak.
const memberLifetime = 24 * time.Hour

// MemberRun is what a member launch produced: the sandbox and the console
// identity of the running instance. The run continues after this returns.
type MemberRun struct {
	SandboxID string
	RunID     string
}

// buildEnv assembles the launch environment: the manifest's static env first,
// then the per-dispatch env, then the injected runtime values (grant,
// endpoints, ids, model, task). Runtime values win on a key clash so neither a
// manifest nor a dispatch can shadow the injected scope.
func (l *AgentLauncher) buildEnv(ctx context.Context, spec AgentLaunchSpec, dispatch AgentDispatch) map[string]string {
	env := make(map[string]string, len(spec.Env)+len(dispatch.Env)+8)
	for k, v := range spec.Env {
		env[k] = v
	}
	for k, v := range dispatch.Env {
		env[k] = v
	}
	if dispatch.Grant != "" {
		env[envAgentGrant] = dispatch.Grant
	}
	if dispatch.CallbackEndpoint != "" {
		env[envAgentCallbackEndpoint] = dispatch.CallbackEndpoint
	}
	if dispatch.MissionID != "" {
		env[envAgentMissionID] = dispatch.MissionID
	}
	if dispatch.MissionRunID != "" {
		env[envAgentMissionRunID] = dispatch.MissionRunID
	}
	if dispatch.AgentRunID != "" {
		env[envAgentAgentRunID] = dispatch.AgentRunID
	}
	if spec.Model != "" {
		env[envAgentModel] = spec.Model
	}
	if dispatch.TaskB64 != "" {
		env[envAgentTaskB64] = dispatch.TaskB64
	}
	// Always set, including for the default shape: a process that has to guess
	// which shape it is would guess wrong exactly once.
	mode := spec.Mode
	if mode == "" {
		mode = "oneshot"
	}
	env[envInstanceMode] = mode
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		env[envTraceID] = sc.TraceID().String()
		env[envSpanID] = sc.SpanID().String()
	}
	return env
}

// LaunchMember starts one bank member and returns as soon as the sandbox is
// running and admitted (ADR-0019 decision 1, gibson#1709).
//
// It is LaunchAgent without the wait: a member serves many jobs over its life,
// so the caller cannot block on its exit. The live-console registration, the
// log tee and the terminal bookkeeping happen in a goroutine that ends when the
// sandbox does. The isolation gate is the same one LaunchAgent applies: a
// member runs untrusted code for longer than a one-shot does, so a sandbox
// whose isolation could not be confirmed is killed, never used.
func (l *AgentLauncher) LaunchMember(ctx context.Context, spec AgentLaunchSpec, dispatch AgentDispatch) (MemberRun, error) {
	if spec.Mode != "member" {
		return MemberRun{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("LaunchMember needs a member launch spec, got mode %q", spec.Mode))
	}
	if spec.Image == "" || len(spec.Command) == 0 {
		return MemberRun{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			"LaunchMember needs an image and a member command")
	}
	class := spec.SandboxClass
	if class == "" {
		class = l.sandboxClass
	}

	ctx, span := l.tracer.Start(ctx, "sandboxed.LaunchMember")
	defer span.End()
	span.SetAttributes(
		attribute.String("agent.name", dispatch.AgentName),
		attribute.String("mission.id", dispatch.MissionID),
	)

	launchCtx, launchSpan := l.tracer.Start(ctx, "setec.launch")
	launchResp, err := l.client.Launch(launchCtx, LaunchRequest{
		Image:        spec.Image,
		Command:      spec.Command,
		Env:          l.buildEnv(ctx, spec, dispatch),
		VCPU:         spec.VCPU,
		Memory:       spec.Memory,
		Tenant:       l.tenant,
		SandboxClass: class,
		Timeout:      memberLifetime + killGrace,
		Egress:       spec.Egress,
	})
	launchSpan.End()
	if err != nil {
		return MemberRun{}, types.WrapError(types.SANDBOX_LAUNCH_FAILED, "launch member sandbox", err)
	}
	span.SetAttributes(attribute.String("setec.sandbox_id", launchResp.SandboxID))

	if isoErr := VerifyIsolation(class, launchResp); isoErr != nil {
		l.kill(ctx, launchResp.SandboxID)
		return MemberRun{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("member sandbox %s refused", launchResp.SandboxID), isoErr)
	}

	runID := runIDFromSandboxID(launchResp.SandboxID)
	var publish func([]byte)
	finish := func() {}
	if l.events != nil {
		publish, finish = l.events.RegisterInstance(dispatch.Tenant, LiveInstance{
			RunID:         runID,
			AgentName:     dispatch.AgentName,
			SandboxID:     launchResp.SandboxID,
			SandboxClass:  class,
			ComponentKind: ComponentKindAgent,
			StartedAt:     time.Now(),
			MissionID:     dispatch.MissionID,
			MissionRunID:  dispatch.MissionRunID,
		})
	}

	// The member outlives the caller's context. The follower runs on its own
	// context, bounded by the sandbox lifetime, so a caller that returns does
	// not tear down the console feed of a member that is still working.
	followCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), memberLifetime+killGrace)
	go l.followMember(followCtx, cancel, launchResp.SandboxID, dispatch, publish, finish)

	l.logger.InfoContext(ctx, "bank member sandbox launched",
		"agent", dispatch.AgentName, "tenant", dispatch.Tenant,
		"sandbox_id", launchResp.SandboxID, "sandbox_class", class)
	return MemberRun{SandboxID: launchResp.SandboxID, RunID: runID}, nil
}

// followMember tees the member's logs to the console until the sandbox ends,
// then deregisters it. It is the tail of LaunchAgent, run in the background.
func (l *AgentLauncher) followMember(ctx context.Context, cancel context.CancelFunc, sandboxID string, dispatch AgentDispatch, publish func([]byte), finish func()) {
	defer cancel()
	defer finish()

	ringBuf := newRing(logBufferLimit)
	terminal := make(chan struct{})
	logsDone := l.streamAgentLogsAsync(ctx, sandboxID, ringBuf, publish, terminal)

	waitResp, waitErr := l.client.Wait(ctx, sandboxID)
	close(terminal)
	<-logsDone

	switch {
	case waitErr != nil && errors.Is(waitErr, context.DeadlineExceeded):
		l.kill(ctx, sandboxID)
		l.logger.WarnContext(ctx, "bank member reached its sandbox lifetime; the reconciler replaces it",
			"agent", dispatch.AgentName, "sandbox_id", sandboxID)
	case waitErr != nil:
		l.logger.WarnContext(ctx, "bank member wait ended with an error",
			"agent", dispatch.AgentName, "sandbox_id", sandboxID, "error", waitErr)
	default:
		l.logger.InfoContext(ctx, "bank member sandbox ended",
			"agent", dispatch.AgentName, "sandbox_id", sandboxID,
			"exit_code", waitResp.ExitCode, "reason", waitResp.Reason, "log_tail", ringBuf.tail(8))
	}
}

// StopSandbox ends a sandbox. The reconciler calls it for a drained member,
// which has no jobs left, and for a dead one, whose process already stopped.
func (l *AgentLauncher) StopSandbox(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return errors.New("sandboxed: StopSandbox: sandbox id is required")
	}
	if err := l.client.Kill(ctx, sandboxID); err != nil {
		return fmt.Errorf("kill sandbox %s: %w", sandboxID, err)
	}
	return nil
}

// kill is the best-effort teardown of a sandbox that must not be used.
func (l *AgentLauncher) kill(ctx context.Context, sandboxID string) {
	killCtx, killCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer killCancel()
	_ = l.client.Kill(killCtx, sandboxID)
}
