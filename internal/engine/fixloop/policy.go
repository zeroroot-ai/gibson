// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import "time"

// Policy is the part of the mission constraints that the Watcher reads
// (gibson#1463, #1507). The tenant states it.
type Policy struct {
	// HoldTime is how long the health signal must hold after the deploy. For a
	// deploy with a restart, it starts when the restart ends.
	HoldTime time.Duration
	// RestartLimit is how long a restart can take before it counts as a
	// failure of the health signal.
	RestartLimit time.Duration
}

// DefaultPolicy is the policy of a tenant that states none.
func DefaultPolicy() Policy {
	return Policy{HoldTime: 10 * time.Minute, RestartLimit: 15 * time.Minute}
}

// PolicySource returns the policy for one tenant.
type PolicySource func(tenant string) Policy
