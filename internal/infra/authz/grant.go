// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"time"
)

// Grant is the post-validation projection of a daemon-minted
// capability-grant JWT. It carries the claims internal services need
// downstream: who minted it, who it covers, what mission task it
// applies to, and when it stops being valid.
type Grant struct {

	// Subject is the sub claim — the agent / tool / plugin
	// principal that presents the grant.
	Subject string

	// Audience is the aud claim — the daemon identifier the grant
	// is targeted at.
	Audience []string

	// ExpiresAt is the exp claim, in UTC. The grant is not valid
	// at or after this instant.
	ExpiresAt time.Time

	// ID is the jti claim — a per-grant unique identifier used by
	// the daemon to revoke individual grants.
	ID string
}
