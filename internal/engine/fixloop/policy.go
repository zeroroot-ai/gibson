// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"time"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// Policy is the part of the mission constraints that the Watcher reads
// (gibson#1463, #1507). The tenant states it.
type Policy struct {
	// HoldTime is how long the health signal must hold after the deploy. For a
	// deploy with a restart, it starts when the restart ends.
	HoldTime time.Duration
	// RestartLimit is how long a restart can take before it counts as a
	// failure of the health signal.
	RestartLimit time.Duration
	// MergeGrantWindow is how long a granted merge slot waits for its merge. When
	// no merge came within the window, the Watcher reads the merge request on the
	// host. A merge request that is still open loses its slot, and the next fix of
	// the Application gets its turn (gibson#1609).
	MergeGrantWindow time.Duration
	// RequeueBackoff is how long the Watcher waits before it queues a merge
	// request again after it freed the slot of that merge request.
	RequeueBackoff time.Duration
	// MergeCallBound is how long a merge call that the gate allowed is on its
	// way to the host. The Watcher frees no slot within it (gibson#1609).
	MergeCallBound time.Duration
}

// DefaultPolicy is the policy of a tenant that states none.
func DefaultPolicy() Policy {
	return Policy{
		HoldTime: 10 * time.Minute, RestartLimit: 15 * time.Minute,
		MergeGrantWindow: 45 * time.Minute, RequeueBackoff: 10 * time.Minute, MergeCallBound: 2 * time.Minute,
	}
}

// PolicySource returns the policy for one tenant.
type PolicySource func(tenant string) Policy

// HoldOf returns the hold time that the constraints of a mission state
// (MissionConstraints.health_hold). It returns zero when the mission states
// none, or states zero, and the Watcher then uses the hold time of the policy.
// The hold time is a constraint of the mission and no setting of a grant.
func HoldOf(c *missionv1.MissionConstraints) time.Duration {
	if hold := c.GetHealthHold().AsDuration(); hold > 0 {
		return hold
	}
	return 0
}

// HoldSource returns the hold time that the fix mission of a merge request
// states, or zero when it states none. An error skips the read of the health
// signal, and the next Step tries it again.
type HoldSource func(ctx context.Context, tenant, missionID string) (time.Duration, error)

// grantWindow is the merge grant window. A policy that states none takes the
// default, so a zero window never frees a slot at the moment of its grant.
func (p Policy) grantWindow() time.Duration {
	if p.MergeGrantWindow <= 0 {
		return DefaultPolicy().MergeGrantWindow
	}
	return p.MergeGrantWindow
}

// requeueBackoff is the backoff before a freed merge request is queued again.
func (p Policy) requeueBackoff() time.Duration {
	if p.RequeueBackoff <= 0 {
		return DefaultPolicy().RequeueBackoff
	}
	return p.RequeueBackoff
}

// callBound is the bound of a merge call that the gate allowed.
func (p Policy) callBound() time.Duration {
	if p.MergeCallBound <= 0 {
		return DefaultPolicy().MergeCallBound
	}
	return p.MergeCallBound
}
