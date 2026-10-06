// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MaxForks is the largest fork count that setec accepts in one request.
const MaxForks = 32

// ForkRequest is the data the launcher passes to the Fork RPC of setec.
// Adapters map it onto the generated proto.
type ForkRequest struct {
	// Tenant is the customer tenant that owns the source sandbox. Only the
	// owner of a sandbox can fork it.
	Tenant string
	// SandboxID names the running source sandbox.
	SandboxID string
	// Count is the number of forks, 1 to MaxForks.
	Count int
	// NetworkMode and Egress are the network of each fork, with the same
	// meaning as on LaunchRequest. The network of the source is never
	// copied (ADR-0169).
	NetworkMode string
	Egress      []EgressRule
	// SnapshotTTL is the lifetime of the snapshot. Zero takes the setec
	// default of one hour.
	SnapshotTTL time.Duration
}

// ForkResponse names the snapshot and the forks, in request order.
type ForkResponse struct {
	Snapshot   string
	SandboxIDs []string
}

// AgentForkSpec is the launch data of a fork. The forks continue the
// process state of the source, so a fork has no image and no command.
type AgentForkSpec struct {
	// SandboxClass is the class that the forks must run under. Empty takes
	// the class of the launcher.
	SandboxClass string
	// NetworkMode and Egress are the network scope of the node that the
	// forks run for. A fork never gets the scope of its source.
	NetworkMode string
	Egress      []EgressRule
	SnapshotTTL time.Duration

	// OnForked runs after setec started the forks and before a fork can call
	// back. The caller records the fork ids there (D74). An error kills each
	// fork, and ForkAgent returns it.
	OnForked func(ForkResponse) error
}

// ForkRun is the outcome of one fork request.
type ForkRun struct {
	// Snapshot is the id of the snapshot that each fork started from. The
	// caller records it as a Timeline event, so a replay names the same
	// state.
	Snapshot string
	// Results holds one outcome for each dispatch, in dispatch order.
	Results []AgentRunResult
	// Errs holds the error of each fork, or nil, in dispatch order.
	Errs []error
}

// ErrForkSource refuses a fork request that names no source sandbox.
var ErrForkSource = errors.New("sandboxed: a fork needs a running source sandbox")

// ForkAgent forks the running source sandbox once for each dispatch, and
// follows each fork to its end as LaunchAgent follows a launch. All forks
// come from one snapshot, so N instances of a for_each start from the same
// state. Every dispatch must name the tenant that owns the source.
func (l *AgentLauncher) ForkAgent(ctx context.Context, sourceSandboxID string, spec AgentForkSpec, dispatches []AgentDispatch) (ForkRun, error) {
	ctx, span := l.tracer.Start(ctx, "harness.sandboxed.fork_agent")
	defer span.End()

	if sourceSandboxID == "" {
		return ForkRun{}, types.WrapError(types.SANDBOX_POLICY_DENIED, "agent fork", ErrForkSource)
	}
	if len(dispatches) == 0 || len(dispatches) > MaxForks {
		return ForkRun{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent fork: %d forks requested, want 1 to %d", len(dispatches), MaxForks))
	}
	tenant := dispatches[0].Tenant
	if tenant == "" {
		return ForkRun{}, types.NewError(types.SANDBOX_POLICY_DENIED, "agent fork: the dispatch names no tenant")
	}
	for _, d := range dispatches[1:] {
		if d.Tenant != tenant {
			return ForkRun{}, types.NewError(types.SANDBOX_POLICY_DENIED,
				"agent fork: each fork must belong to the tenant of the source")
		}
	}
	class := spec.SandboxClass
	if class == "" {
		class = l.sandboxClass
	}
	span.SetAttributes(
		attribute.String("setec.tenant", tenant),
		attribute.String("setec.source_sandbox_id", sourceSandboxID),
		attribute.Int("setec.fork_count", len(dispatches)),
	)

	forkCtx, forkSpan := l.tracer.Start(ctx, "setec.fork")
	resp, err := l.client.Fork(forkCtx, ForkRequest{
		Tenant:      tenant,
		SandboxID:   sourceSandboxID,
		Count:       len(dispatches),
		NetworkMode: spec.NetworkMode,
		Egress:      spec.Egress,
		SnapshotTTL: spec.SnapshotTTL,
	})
	forkSpan.End()
	if err != nil {
		return ForkRun{}, types.WrapError(types.SANDBOX_LAUNCH_FAILED, "fork agent sandbox "+sourceSandboxID, err)
	}
	if len(resp.SandboxIDs) != len(dispatches) {
		for _, id := range resp.SandboxIDs {
			l.kill(ctx, tenant, id)
		}
		return ForkRun{}, types.NewError(types.SANDBOX_LAUNCH_FAILED,
			fmt.Sprintf("agent fork: setec started %d forks, want %d", len(resp.SandboxIDs), len(dispatches)))
	}
	span.SetAttributes(attribute.String("setec.snapshot", resp.Snapshot))
	if spec.OnForked != nil {
		if err := spec.OnForked(resp); err != nil {
			for _, id := range resp.SandboxIDs {
				l.kill(ctx, tenant, id)
			}
			return ForkRun{}, types.WrapError(types.SANDBOX_LAUNCH_FAILED, "record the forks of "+sourceSandboxID, err)
		}
	}

	run := ForkRun{
		Snapshot: resp.Snapshot,
		Results:  make([]AgentRunResult, len(dispatches)),
		Errs:     make([]error, len(dispatches)),
	}
	var wg sync.WaitGroup
	for i, d := range dispatches {
		wg.Add(1)
		go func(i int, d AgentDispatch, sandboxID string) {
			defer wg.Done()
			run.Results[i], run.Errs[i] = l.followFork(ctx, tenant, sandboxID, class, d)
		}(i, d, resp.SandboxIDs[i])
	}
	wg.Wait()
	return run, nil
}

// followFork checks the isolation of one fork, and follows it to its end.
func (l *AgentLauncher) followFork(ctx context.Context, tenant, sandboxID, class string, d AgentDispatch) (AgentRunResult, error) {
	if isoErr := VerifyIsolation(class, LaunchResponse{SandboxID: sandboxID}); isoErr != nil {
		l.kill(ctx, tenant, sandboxID)
		return AgentRunResult{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent fork %s refused", sandboxID), isoErr)
	}
	runTimeout := l.runTimeout
	if d.RunTimeout > 0 {
		runTimeout = d.RunTimeout
	}
	return l.followRun(ctx, tenant, sandboxID, class, runTimeout, d)
}

// EnvForkable tells a process that a later node may fork it (sdk#248).
const EnvForkable = "GIBSON_FORKABLE"

// parkPoll is how often the launcher looks for the result line of a
// forkable source.
const parkPoll = 200 * time.Millisecond

// awaitParkedResult returns when the forkable source wrote its result line,
// with parked true. It returns parked false when the sandbox ends first or
// ctx ends, and the caller then waits for the terminal phase as for any run.
func (l *AgentLauncher) awaitParkedResult(ctx context.Context, tenant, sandboxID string, rb *ring) (AgentRunResult, bool) {
	ended := make(chan struct{})
	waitCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		defer close(ended)
		_, _ = l.client.Wait(waitCtx, tenant, sandboxID)
	}()
	tick := time.NewTicker(parkPoll)
	defer tick.Stop()
	for {
		if r := parseTerminalResult(rb.bytes()); r != nil {
			return AgentRunResult{SandboxID: sandboxID, Result: r, Parked: true, LogTail: rb.tail(32)}, true
		}
		select {
		case <-ended:
			return AgentRunResult{}, false
		case <-ctx.Done():
			return AgentRunResult{}, false
		case <-tick.C:
		}
	}
}
