// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package sandboxed — ephemeral agent dispatch (gibson#1596, ADR-0116).
//
// The per-call path in executor.go launches a microVM, runs one command, and
// destroys it. That is request/response, correct for a tool call. An AGENT is
// different: it is a long-running process that runs a whole mission run (many
// internal steps), emits structured output over its run, and returns a terminal
// result. ADR-0116 dispatches such an agent as an ephemeral, per-mission-run
// Setec sandbox instead of a long-lived shared worker, so one compromised run
// reaches only one tenant's one run.
//
// AgentLauncher is the agent counterpart of Executor. It Launches a sandbox for
// the agent, streams its logs (so a later live-console slice can subscribe),
// waits for the terminal phase + exit status, and lets setec's finished-TTL
// reaper tear it down. It carries NO result blob back through setec: the agent
// returns its structured mission result over its own callback seam to the
// daemon (HarnessCallbackService), not through the sandbox transport, which
// only reports exit status and streamed stdout.
//
// Like the rest of this package it has ZERO setec imports — the daemon's setec
// adapter (built under //go:build setec_integration) is the single point of
// contact, exactly as it is for the tool Executor.
package sandboxed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Environment variables injected into every agent sandbox launch. The agent
// image reads these to reach the daemon back and to scope itself to the one
// dispatch it was launched for (ADR-0116 — nothing standing).
const (
	// envAgentGrant carries the per-dispatch capability-grant JWT. It is
	// tenant+run-scoped with a short TTL; the agent presents it on harness
	// callbacks and it dies when the run ends.
	envAgentGrant = "GIBSON_CG_JWT"
	// envAgentCallbackEndpoint is the HarnessCallbackService address the agent
	// dials to reach LLM/tools/findings and to return its mission result.
	envAgentCallbackEndpoint = "GIBSON_CALLBACK_ENDPOINT"
	// envPlatformCAPEM carries the platform's edge CA as PEM. A sandbox
	// cannot mount the Secret in-cluster consumers trust the edge through,
	// and a private edge CA (kind, a self-hosted install) is not in the
	// image's roots, so the agent verified nothing and every callback and
	// heartbeat died at TLS (gibson#13, run 35478182465). The driver writes
	// it to a file and trusts it beside the public roots. Absent when the
	// edge chains to public roots.
	envPlatformCAPEM = "GIBSON_PLATFORM_CA_PEM"
	// envAgentMissionID / envAgentMissionRunID / envAgentAgentRunID scope the
	// callbacks to this mission run.
	envAgentMissionID    = "GIBSON_MISSION_ID"
	envAgentMissionRunID = "GIBSON_MISSION_RUN_ID"
	envAgentAgentRunID   = "GIBSON_AGENT_RUN_ID"
	// envAgentModel is the model resolved for the tenant at dispatch time
	// (ADR-0116 — the signed manifest does not pin a model).
	envAgentModel = "GIBSON_MODEL"
	// envAgentTaskB64 carries the base64 protojson of the agent.Task the run
	// must execute. The agent decodes it on start.
	envAgentTaskB64 = "GIBSON_AGENT_TASK_B64"
	// envInstanceMode tells the process which of the two shapes it is running
	// as (ADR-0119): "oneshot" serves one dispatch and ends, "member" serves
	// many over its life. One image carries both, so the process reads this
	// rather than inferring it from what it was given.
	envInstanceMode = "GIBSON_INSTANCE_MODE"
	// envSandbox tells the process which isolation it runs under. The
	// zerocool-claude member refuses to start without the gvisor marker
	// (zerocool-plugins#66): it keeps --dangerously-skip-permissions only
	// inside a sandbox, and the marker is how it knows it is in one. Both
	// launch paths land in the gVisor class and VerifyIsolation kills a
	// sandbox that is not (ADR-0052), so the marker states a fact the
	// launcher enforces, never a wish.
	envSandbox      = "GIBSON_SANDBOX"
	envSandboxValue = "gvisor"
)

// defaultAgentRunTimeout bounds one agent mission run when the launcher config
// leaves RunTimeout zero. An agent runs a whole mission, so this is far longer
// than the per-tool call timeout.
const defaultAgentRunTimeout = 30 * time.Minute

// AgentLaunchSpec is the per-agent launch shape sourced from the signed catalog
// manifest (ADR-0136 / ADR-0116). It is the typed seam for gibson#1597 (S5):
// this slice accepts it as a parameter and drives it in tests; S5 feeds the
// real manifest values (image, sandbox class, egress ceiling, resolved model).
// Nothing here is agent-specific in code — no zerocool constants live in this
// package.
type AgentLaunchSpec struct {
	// Image is the agent OCI image to run.
	Image string
	// Command overrides the image entrypoint. Empty keeps the image default.
	Command []string
	// Env is static, non-secret environment from the manifest. Per-dispatch
	// runtime values (grant, endpoints, ids, task) are added by Launch and win
	// on a key clash.
	Env map[string]string
	// VCPU and Memory are the sandbox resource request.
	VCPU   int32
	Memory string
	// SandboxClass names the setec SandboxClass this agent runs under
	// (ADR-0116 — gVisor by default in production). Empty defers to
	// the launcher's deployment-default class.
	SandboxClass string
	// Egress is the tenant egress envelope (ADR-0116). Empty keeps
	// setec's default network mode; a non-empty list confines the sandbox to
	// exactly these targets. Build it from a manifest egressAllow ceiling with
	// EgressRulesFromAllow.
	Egress []EgressRule
	// NetworkMode, when set, is the network mode of the launch. It carries
	// the network scope of the mission node (gibson#865).
	NetworkMode string
	// Model is the model string resolved for the tenant at dispatch. Injected
	// as GIBSON_MODEL so the signed manifest never goes stale as models ship.
	Model string
	// Mode is the instance shape this launch runs: "oneshot" (the default) or
	// "member". Injected as GIBSON_INSTANCE_MODE.
	Mode string
	// MaxRuntime is the cap the agent's enrollment declares for one run
	// (AgentEnrollmentSpec.maxRuntime, gibson#597). Zero means no enrollment
	// cap; the dispatch's own RunTimeout and the launcher default apply.
	MaxRuntime time.Duration
}

// AgentDispatch is the per-dispatch runtime scope injected into the sandbox:
// the tenant+run-scoped capability grant and the endpoints and ids the agent
// needs to reach the daemon back and return its result. It holds only that
// run's scope — no standing identity and no cross-tenant membership (ADR-0116).
type AgentDispatch struct {
	// Grant is the per-dispatch CG-JWT (short TTL, tenant+run scoped).
	Grant string
	// CallbackEndpoint is the HarnessCallbackService address the agent dials.
	CallbackEndpoint string
	// MissionID, MissionRunID and AgentRunID scope the callbacks and the result.
	MissionID    string
	MissionRunID string
	AgentRunID   string
	// TaskB64 is the base64 protojson of the agent.Task to run.
	TaskB64 string
	// Tenant is the CUSTOMER tenant that owns this mission run, derived from the
	// caller's authenticated context. setec gets it on each request
	// (ADR-0142), and the live-console registry keys instances by it, so a
	// subscriber only ever sees its own tenant's runs (ADR-0116 S11).
	Tenant string
	// AgentName is the dispatched agent's name, shown in the running-instance
	// enumeration.
	AgentName string
	// Env is per-dispatch environment that is neither the manifest's static
	// env nor one of the injected runtime keys: a member's ids and its bank's
	// policy (ADR-0119). It is applied after the manifest env and before the
	// runtime keys, so it can never shadow the injected scope either.
	Env map[string]string
	// RunTimeout is this dispatch's own bound, taken from the mission node's
	// declared timeout. Zero falls back to the launcher default.
	//
	// The bound has to arrive per dispatch, not per launcher: a launcher serves
	// every agent run in the process, so a launcher-wide default capped a live
	// session at thirty minutes no matter what its node declared, which is what
	// made an always-on agent impossible (gibson#1602).
	RunTimeout time.Duration

	// Forkable marks the source of a later node (ADR-0169, D74). The process
	// gets GIBSON_FORKABLE=1 and parks after its result line, and the
	// launcher returns at that line and leaves the sandbox running.
	Forkable bool
}

// EventPublisher registers a running agent instance and returns a live sink for
// its structured events. The launcher taps its sandbox log stream into publish
// while the run is live and calls finish at the run's terminal state. It is the
// seam to the daemon's live-console registry (ADR-0116 S11); the launcher never
// imports that registry, only this interface. A nil publisher disables the live
// console — the launcher still streams to the ring buffer and the logger.
type EventPublisher interface {
	// RegisterInstance records one running instance and returns publish (tee one
	// event chunk to subscribers) and finish (deregister and close the feed,
	// called once at terminal state).
	RegisterInstance(tenant string, inst LiveInstance) (publish func([]byte), finish func())
}

// LiveInstance describes one running agent instance to the EventPublisher:
// the run handle, what runs, where it runs, and the mission it serves.
type LiveInstance struct {
	// RunID uniquely identifies this running instance within the tenant.
	RunID string
	// AgentName is the dispatched agent's name.
	AgentName string
	// SandboxID is the setec sandbox backing this run.
	SandboxID string
	// SandboxClass is the setec SandboxClass this run was launched under.
	SandboxClass string
	// ComponentKind is what kind of component is running: "agent" or "tool".
	// Both take a sandbox, and the console shows both, so a viewer needs to
	// tell a coding agent from a port scan at a glance.
	ComponentKind string
	// StartedAt is when the instance was registered (dispatch start).
	StartedAt time.Time
	// MissionID and MissionRunID are the mission and the mission run this
	// instance serves. Empty for a run outside a mission.
	MissionID    string
	MissionRunID string
}

// AgentRunResult is the terminal outcome of one agent sandbox run. It reports
// how the sandbox ended and the structured result that the agent wrote.
// LogTail is the last streamed stdout lines, kept for diagnostics on a
// non-zero exit.
type AgentRunResult struct {
	SandboxID string
	ExitCode  int32
	Reason    string
	LogTail   string

	// Result is the terminal result line of the agent. It is nil when the
	// agent wrote none.
	Result *AgentTerminalResult

	// Parked is true for a forkable source whose node ended at its result
	// line. Its sandbox still runs, so a later node can fork it (D74).
	Parked bool
}

// AgentTerminalResult is the structured result of one sandboxed agent run.
// The agent writes it as the last NDJSON line on its stdout, with
// `"type":"result"`, before it exits:
//
//	{"type":"result","success":true,"output":"...","finding_ids":["..."],"metadata":{"k":"v"}}
//
// The line is the word of the agent about its own run, like each other
// output of a sandbox. The exit status still comes from setec.
type AgentTerminalResult struct {
	Success    bool           `json:"success"`
	Output     string         `json:"output"`
	FindingIDs []string       `json:"finding_ids,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// terminalResultType is the value of the `type` key that marks the result
// line apart from the event lines on the same stream.
const terminalResultType = "result"

// parseTerminalResult returns the last complete result line in the stdout of
// an agent run, or nil when the stream holds none. A line that is not JSON,
// or that has a different type, is an event line and is ignored.
func parseTerminalResult(stdout []byte) *AgentTerminalResult {
	lines := bytes.Split(stdout, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var probe struct {
			Type string `json:"type"`
			AgentTerminalResult
		}
		if err := json.Unmarshal(line, &probe); err != nil || probe.Type != terminalResultType {
			continue
		}
		res := probe.AgentTerminalResult
		return &res
	}
	return nil
}

// AgentLauncher launches an untrusted/sandboxed agent as an ephemeral Setec
// sandbox for one mission run and waits for its terminal outcome. It is the
// agent-process counterpart of Executor and is safe for concurrent use:
// per-launch state lives on the stack of LaunchAgent.
type AgentLauncher struct {
	client       SandboxClient
	tracer       trace.Tracer
	logger       *slog.Logger
	sandboxClass string
	runTimeout   time.Duration
	events       EventPublisher
	platformCA   string
}

// AgentLauncherConfig is the constructor input for AgentLauncher. Client is
// required. Each launch names the customer tenant of its dispatch. SandboxClass is the deployment-default class an
// AgentLaunchSpec may override; it is required so a launch can never inherit
// the cluster-default isolation posture (ADR-0052). Tracer, Logger and
// RunTimeout default when unset.
type AgentLauncherConfig struct {
	Client       SandboxClient
	Tracer       trace.Tracer
	Logger       *slog.Logger
	SandboxClass string
	RunTimeout   time.Duration
	// Events is the live-console sink for running-agent structured events
	// (ADR-0116 S11). Nil disables the live console; the launcher still tees the
	// sandbox log to the ring buffer and the daemon logger.
	Events EventPublisher
	// PlatformCAPEM is the platform edge CA, as PEM, handed to every launch
	// in GIBSON_PLATFORM_CA_PEM. Empty means the edge chains to public
	// roots and nothing is handed over.
	PlatformCAPEM string
}

// NewAgentLauncher constructs an AgentLauncher. It returns a clear error on
// misconfiguration so the daemon can log a warning and continue without
// sandboxed agent dispatch (the harness then denies untrusted agents
// fail-closed).
func NewAgentLauncher(cfg AgentLauncherConfig) (*AgentLauncher, error) {
	if cfg.Client == nil {
		return nil, errors.New("sandboxed.NewAgentLauncher: Client is required")
	}
	if cfg.SandboxClass == "" {
		return nil, errors.New("sandboxed.NewAgentLauncher: SandboxClass is required (ADR-0052: gibson must name the isolation posture, not inherit the cluster default)")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Tracer == nil {
		cfg.Tracer = noop.NewTracerProvider().Tracer("gibson.sandboxed.agent")
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = defaultAgentRunTimeout
	}
	return &AgentLauncher{
		client:       cfg.Client,
		tracer:       cfg.Tracer,
		logger:       cfg.Logger,
		sandboxClass: cfg.SandboxClass,
		runTimeout:   cfg.RunTimeout,
		events:       cfg.Events,
		platformCA:   cfg.PlatformCAPEM,
	}, nil
}

// LaunchAgent launches a fresh Setec sandbox for one mission run, injects the
// per-dispatch grant and egress envelope, streams the run's logs, and waits for
// the terminal phase + exit status. It returns the terminal AgentRunResult.
//
// The agent writes its structured mission result as the last result line on
// its stdout (AgentTerminalResult), and LaunchAgent returns it with the exit
// status. Teardown is left to setec's finished-TTL reaper; on a timeout the
// sandbox is killed best-effort so it is reaped promptly rather than left
// running.
func (l *AgentLauncher) LaunchAgent(ctx context.Context, spec AgentLaunchSpec, dispatch AgentDispatch) (AgentRunResult, error) {
	ctx, span := l.tracer.Start(ctx, "harness.sandboxed.launch_agent")
	defer span.End()
	span.SetAttributes(attribute.String("setec.tenant", dispatch.Tenant))

	if spec.Image == "" {
		return AgentRunResult{}, types.WrapError(types.SANDBOX_TOOL_NOT_REGISTERED,
			"agent launch: empty image in AgentLaunchSpec", nil)
	}
	// The customer tenant of the dispatch names the setec namespace
	// (ADR-0142). A dispatch with no tenant does not launch.
	tenant := dispatch.Tenant
	if tenant == "" {
		return AgentRunResult{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			"agent launch: the dispatch names no tenant", nil)
	}

	// SandboxClass precedence: the manifest spec wins; the launcher's
	// deployment default fills in when the spec omits one.
	class := spec.SandboxClass
	if class == "" {
		class = l.sandboxClass
	}

	env := l.buildEnv(ctx, spec, dispatch)

	// This dispatch's bound: the node's declared timeout when it has one, the
	// launcher default otherwise (gibson#1602).
	runTimeout := l.runTimeout
	if dispatch.RunTimeout > 0 {
		runTimeout = dispatch.RunTimeout
	}

	// Launch. The sandbox lifetime is the run timeout plus a kill grace so
	// setec reaps a run that overshoots its budget.
	launchCtx, launchSpan := l.tracer.Start(ctx, "setec.launch")
	launchResp, err := l.client.Launch(launchCtx, LaunchRequest{
		Image:        spec.Image,
		Command:      spec.Command,
		Env:          env,
		VCPU:         spec.VCPU,
		Memory:       spec.Memory,
		Tenant:       tenant,
		SandboxClass: class,
		Timeout:      runTimeout + killGrace,
		Egress:       spec.Egress,
		NetworkMode:  spec.NetworkMode,
	})
	launchSpan.End()
	if err != nil {
		return AgentRunResult{}, types.WrapError(types.SANDBOX_LAUNCH_FAILED,
			"launch agent sandbox", err)
	}
	span.SetAttributes(attribute.String("setec.sandbox_id", launchResp.SandboxID))

	// Isolation gate (ADR-0052 / ADR-0116). The sandbox exists but
	// the agent has not run yet — this is the last point at which we can refuse
	// it. An agent runs untrusted code by construction, so a sandbox whose
	// isolation we could not confirm is killed, not used.
	if isoErr := VerifyIsolation(class, launchResp); isoErr != nil {
		killCtx, killCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = l.client.Kill(killCtx, tenant, launchResp.SandboxID)
		killCancel()
		return AgentRunResult{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent sandbox %s refused", launchResp.SandboxID), isoErr)
	}
	span.SetAttributes(attribute.String("setec.sandbox_class", class))

	return l.followRun(ctx, tenant, launchResp.SandboxID, class, runTimeout, dispatch)
}

// followRun follows one running agent sandbox to its terminal outcome: it
// registers the run on the live console, tees its logs, waits for the end
// and parses the terminal result line. A launched sandbox and a fork take
// the same path.
func (l *AgentLauncher) followRun(ctx context.Context, tenant, sandboxID, class string, runTimeout time.Duration, dispatch AgentDispatch) (AgentRunResult, error) {

	// Register this run as a live instance so a read-only subscriber can follow
	// its structured events (ADR-0116 S11). The instance is keyed by the CUSTOMER
	// tenant on the dispatch. finish deregisters and
	// closes every subscriber stream at the terminal state below. A nil publisher
	// (live console disabled) yields no-op publish/finish.
	var publish func([]byte)
	var finish func()
	if l.events != nil {
		publish, finish = l.events.RegisterInstance(dispatch.Tenant, LiveInstance{
			RunID:         dispatchRunID(dispatch, sandboxID),
			AgentName:     dispatch.AgentName,
			SandboxID:     sandboxID,
			SandboxClass:  class,
			ComponentKind: ComponentKindAgent,
			StartedAt:     time.Now(),
			MissionID:     dispatch.MissionID,
			MissionRunID:  dispatch.MissionRunID,
		})
		defer finish()
	}

	// Stream logs concurrently with Wait, bounded by the run timeout.
	waitCtx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	ringBuf := newRing(logBufferLimit)
	// terminal closes once Wait returns, so the log tee stops re-attaching to a
	// run that has already ended.
	terminal := make(chan struct{})
	logsDone := l.streamAgentLogsAsync(waitCtx, tenant, sandboxID, ringBuf, publish, terminal)

	// A forkable source parks after its result line and does not exit
	// (D74). Its node ends at the result line, and the sandbox stays for the
	// later node that forks it.
	if dispatch.Forkable {
		if res, parked := l.awaitParkedResult(waitCtx, tenant, sandboxID, ringBuf); parked {
			close(terminal)
			cancel()
			<-logsDone
			return res, nil
		}
	}

	// Wait for the terminal phase.
	waitCtx2, waitSpan := l.tracer.Start(waitCtx, "setec.wait")
	waitResp, waitErr := l.client.Wait(waitCtx2, tenant, sandboxID)
	waitSpan.End()
	close(terminal)

	// Let the log stream finish draining (bounded by waitCtx).
	<-logsDone

	if waitErr != nil {
		if errors.Is(waitErr, context.DeadlineExceeded) {
			// Kill so setec reaps the run rather than letting it keep going.
			killCtx, killCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = l.client.Kill(killCtx, tenant, sandboxID)
			killCancel()
			return AgentRunResult{SandboxID: sandboxID}, types.WrapError(types.SANDBOX_WAIT_TIMEOUT,
				"agent sandbox "+sandboxID+" exceeded "+runTimeout.String()+" run timeout", waitErr)
		}
		return AgentRunResult{SandboxID: sandboxID}, types.WrapError(types.SANDBOX_LAUNCH_FAILED,
			"wait for agent sandbox "+sandboxID, waitErr)
	}

	return AgentRunResult{
		SandboxID: sandboxID,
		ExitCode:  waitResp.ExitCode,
		Reason:    waitResp.Reason,
		LogTail:   ringBuf.tail(32),
		Result:    parseTerminalResult(ringBuf.bytes()),
	}, nil
}

// Component kinds a sandbox run can carry on the live console.
const (
	// ComponentKindAgent is a dispatched agent: it pursues a goal and calls
	// back into the harness.
	ComponentKindAgent = "agent"
	// ComponentKindTool is a single tool invocation: one command, one result.
	ComponentKindTool = "tool"
)

// dispatchRunID returns the console identity for one sandbox dispatch.
//
// It is the sandbox id, which is unique per launch by construction. Mission
// ids are NOT unique per dispatch: every agent node in one mission run shares
// MissionRunID, so keying by it made two agents in the same mission collide.
// The registry treats a duplicate run id as a replacement and closes the older
// feed, so one tile appeared where two agents were running, bound to whichever
// registered last and streaming nothing. Mission scope is not lost — MissionID
// and MissionRunID are carried on their own fields.
func dispatchRunID(_ AgentDispatch, sandboxID string) string {
	return runIDFromSandboxID(sandboxID)
}

// runIDFromSandboxID reduces a sandbox id to the console run id.
//
// setec reports a sandbox id as "<namespace>/<name>/<uid>". The run id has to
// be ONE opaque token: the console addresses a stream at
// /api/agents/<run-id>/events, a single path segment, so a value carrying
// slashes produces a URL that cannot route and every tile streams nothing.
// The trailing uid is unique per launch, which is the property the run id
// needs. The full sandbox id is still reported on its own field.
func runIDFromSandboxID(sandboxID string) string {
	if i := strings.LastIndex(sandboxID, "/"); i >= 0 && i+1 < len(sandboxID) {
		return sandboxID[i+1:]
	}
	return sandboxID
}

// streamAgentLogsAsync consumes the sandbox log stream, mirrors each chunk to
// the ring buffer AND the harness logger (so operators see agent output in the
// normal daemon log pipeline) AND the live-console publish sink when one is
// wired, and returns a channel that closes when the stream drains. This path
// only tees the stream; it does not parse it. A nil publish sink means the live
// console is disabled.
// logAttachBackoff bounds the pause between attempts to attach the log tee
// to a sandbox that is not loggable yet.
const (
	logAttachBackoffStart = 500 * time.Millisecond
	logAttachBackoffCap   = 10 * time.Second
)

// streamAgentLogsAsync tees the sandbox log into the ring buffer and the live
// publisher until the stream ends. A sandbox that is still Pending (queued for
// CPU behind other runs) is not loggable yet: setec answers the attach with
// FailedPrecondition, and the first chunk never comes. The tee re-attaches
// with backoff until the first chunk arrives, the context ends, or the run
// reaches its terminal phase (terminal closes). After the first chunk a
// recv error ends the tee, as a re-attach would replay what was seen.
func (l *AgentLauncher) streamAgentLogsAsync(ctx context.Context, tenant, sandboxID string, rb *ring, publish func([]byte), terminal <-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		backoff := logAttachBackoffStart
		for attempt := 1; ; attempt++ {
			attached, err := l.teeAgentLogs(ctx, tenant, sandboxID, rb, publish)
			if err == nil || attached {
				return
			}
			if ctx.Err() != nil {
				return
			}
			select {
			case <-terminal:
				l.logger.Warn("agent sandbox log tee never attached; run ended",
					"sandbox_id", sandboxID, "attempts", attempt, "error", err)
				return
			default:
			}
			l.logger.Warn("agent sandbox log attach failed; retrying",
				"sandbox_id", sandboxID, "attempt", attempt, "backoff", backoff.String(), "error", err)
			select {
			case <-ctx.Done():
				return
			case <-terminal:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > logAttachBackoffCap {
				backoff = logAttachBackoffCap
			}
		}
	}()
	return done
}

// teeAgentLogs runs one attach-and-drain of the sandbox log stream. It
// reports whether at least one chunk arrived and the error that ended the
// stream, nil for a clean end (EOF or context cancel).
func (l *AgentLauncher) teeAgentLogs(ctx context.Context, tenant, sandboxID string, rb *ring, publish func([]byte)) (attached bool, err error) {
	stream, err := l.client.StreamLogs(ctx, tenant, sandboxID)
	if err != nil {
		return false, fmt.Errorf("open agent sandbox log stream: %w", err)
	}
	defer func() { _ = stream.Close() }()
	for {
		chunk, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) || errors.Is(recvErr, context.Canceled) {
			return attached, nil
		}
		if recvErr != nil {
			if attached {
				l.logger.Warn("agent sandbox log recv error",
					"sandbox_id", sandboxID, "error", recvErr)
			}
			return attached, fmt.Errorf("recv agent sandbox log: %w", recvErr)
		}
		attached = true
		rb.write(chunk)
		if publish != nil {
			publish(chunk)
		}
		// The chunk itself is never logged: an agent's stdout can carry a
		// sign-in URL or a credential prompt (ADR-0119), and a
		// debug log is not a place a secret may land. The size is enough to
		// see the feed move.
		l.logger.Debug("agent sandbox log",
			"sandbox_id", sandboxID, "bytes", len(chunk))
	}
}
