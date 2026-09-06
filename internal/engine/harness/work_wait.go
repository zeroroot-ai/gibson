// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// work_wait.go decides how long a dispatched work item is waited on, and it is
// the reason a live agent node can outlive the five-minute work-queue default
// (gibson#1602).
//
// Before this, every dispatch — tool, plugin, agent — waited exactly
// workQueueWaitTimeout(), one harness-wide value. A coding-agent session is one
// AGENT node that runs for hours, so its node failed after five minutes while
// the agent was still working, and MissionNode.timeout never reached the wait.
//
// Two things change here:
//
//   - A node's own declared timeout bounds its wait. Nothing else does.
//   - An agent node that declares no timeout is bounded by its WORKER'S
//     LIVENESS instead of by a clock. It waits while the worker keeps
//     heartbeating and fails as soon as the worker is gone.
//
// Why liveness and not the pending-entries list. The issue proposed detecting a
// vanished worker with ReclaimAbandoned's idle detection. That signal is wrong
// for exactly this case: XPENDING idle time measures time since DELIVERY, not
// worker health, so a healthy agent that has held one work item for eight hours
// looks maximally "abandoned" and would be killed precisely when the feature is
// working. The component registry is the real liveness signal — an instance key
// carries a TTL that the worker refreshes on a heartbeat, so its disappearance
// means the worker stopped, and nothing else does.

package harness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

const (
	// livenessProbeInterval is how often an unbounded wait re-checks that the
	// worker is still registered. The registry TTL is thirty seconds, refreshed
	// by a ten-second heartbeat, so probing on the TTL cadence sees a departure
	// within one interval of it becoming true.
	livenessProbeInterval = 30 * time.Second

	// livenessGraceProbes is how many consecutive probes must find the worker
	// absent before the wait gives up. Three probes is ninety seconds — three
	// missed heartbeat windows — which distinguishes a worker that stopped from
	// a Redis blip or a slow refresh. A single absent probe is not evidence.
	livenessGraceProbes = 3
)

// waitPolicy is how one dispatch decides its bound.
type waitPolicy struct {
	// bound is the node's declared timeout (MissionNode.timeout). Zero means the
	// node declared none.
	bound time.Duration

	// livenessBounded lets an undeclared bound mean "wait while the worker
	// lives" rather than "fall back to the work-queue default". Only agent
	// dispatch sets it: a tool call that hangs is a bug, and capping it at the
	// default is the behaviour every tool has always had.
	livenessBounded bool

	// tenant, kind, name and instanceID identify the worker whose liveness a
	// liveness-bounded wait probes.
	tenant     string
	kind       string
	name       string
	instanceID string
}

// deadline reports the wall-clock bound for this policy and whether one exists.
// A declared timeout always wins. With no declared timeout, a liveness-bounded
// wait has no clock bound at all; anything else keeps the harness default.
func (p waitPolicy) deadline(def time.Duration, now time.Time) (time.Time, bool) {
	if p.bound > 0 {
		return now.Add(p.bound), true
	}
	if p.livenessBounded {
		return time.Time{}, false
	}
	return now.Add(def), true
}

// probeInterval is how often an unbounded wait re-checks worker liveness.
// livenessProbeEvery is a test seam so a liveness test runs in milliseconds
// rather than minutes; production leaves it zero and gets the constant.
func (h *DefaultAgentHarness) probeInterval() time.Duration {
	if h.livenessProbeEvery > 0 {
		return h.livenessProbeEvery
	}
	return livenessProbeInterval
}

// errWorkerGone reports that the worker holding a work item stopped heartbeating
// before it delivered a result. It is a failure, not a timeout: the node failed
// because nothing is left to answer it.
var errWorkerGone = errors.New("worker is no longer registered")

// waitForWorkResult waits for a dispatched work item under policy p.
//
// A bounded wait is one WaitForResult call, exactly as before. An unbounded wait
// polls in livenessProbeInterval slices, checking the worker's registration
// between slices, so a vanished worker fails the node instead of hanging it
// forever. The parent context always wins: mission cancellation ends the wait.
func (h *DefaultAgentHarness) waitForWorkResult(
	ctx context.Context,
	workID string,
	p waitPolicy,
) (*component.WorkResult, error) {
	deadline, bounded := p.deadline(h.workQueueWaitTimeout(), time.Now())

	// An unbounded wait needs a way to observe the worker leaving. Without a
	// registry there is none, and waiting forever on a worker that may already
	// be gone is worse than the bound this replaces — so fall back to it and
	// say so once.
	if !bounded && h.componentRegistry == nil {
		h.logger.Warn("no component registry: cannot bound a live agent wait by worker liveness, using the work-queue default",
			"kind", p.kind, "component", p.name, "work_id", workID,
			"default", h.workQueueWaitTimeout().String())
		deadline, bounded = time.Now().Add(h.workQueueWaitTimeout()), true
	}

	if bounded {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("work %s: node timeout %s already elapsed before the wait began", workID, p.bound)
		}
		result, err := h.workQueue.WaitForResult(ctx, workID, remaining)
		if err != nil {
			return nil, fmt.Errorf("wait for work %s: %w", workID, err)
		}
		return result, nil
	}

	absent := 0
	for {
		result, err := h.workQueue.WaitForResult(ctx, workID, h.probeInterval())
		if err == nil {
			return result, nil
		}
		// Only a slice expiry continues the loop. Anything else — a cancelled
		// mission, an unknown work id, a Redis failure — is returned as it is,
		// because retrying it would just fail the same way.
		if !errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("wait for work %s: %w", workID, err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("wait for work %s: %w", workID, ctxErr)
		}

		alive, probeErr := h.workerAlive(ctx, p)
		switch {
		case probeErr != nil:
			// A probe that cannot answer is not evidence of departure. Keep
			// waiting and let the next probe decide.
			h.logger.Warn("worker liveness probe failed; continuing to wait",
				"kind", p.kind, "component", p.name, "work_id", workID, "error", probeErr)
		case alive:
			absent = 0
		default:
			absent++
			h.logger.Warn("worker not found in the registry while waiting for its result",
				"kind", p.kind, "component", p.name, "work_id", workID,
				"consecutive_absent_probes", absent, "grace_probes", livenessGraceProbes)
			if absent >= livenessGraceProbes {
				return nil, fmt.Errorf("work %s: %w (absent for %s; it never delivered a result)",
					workID, errWorkerGone, time.Duration(absent)*h.probeInterval())
			}
		}
	}
}

// workerAlive reports whether the dispatched worker is still registered.
//
// When the dispatch recorded which instance took the work, that exact instance
// must still be present: another instance of the same component is a different
// process and is not holding this work item. When no instance was recorded, any
// live instance of the component counts.
func (h *DefaultAgentHarness) workerAlive(ctx context.Context, p waitPolicy) (bool, error) {
	instances, err := h.componentRegistry.Discover(ctx, p.tenant, p.kind, p.name)
	if err != nil {
		return false, fmt.Errorf("discover %s %q: %w", p.kind, p.name, err)
	}
	if p.instanceID == "" {
		return len(instances) > 0, nil
	}
	for _, inst := range instances {
		if inst.InstanceID == p.instanceID {
			return true, nil
		}
	}
	return false, nil
}
