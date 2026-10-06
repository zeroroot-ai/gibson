// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"time"
)

// Grant is the post-validation projection of a daemon-minted
// capability-grant JWT. It carries the claims internal services need
// downstream: who minted it, who it covers, what mission task it
// applies to, and when it stops being valid.
type Grant struct {
	// Issuer is the iss claim — the daemon's CG authority URL.
	Issuer string

	// Subject is the sub claim — the agent / tool / plugin
	// principal that presents the grant.
	Subject string

	// Audience is the aud claim — the daemon identifier the grant
	// is targeted at.
	Audience []string

	// IssuedAt is the iat claim, in UTC.
	IssuedAt time.Time

	// NotBefore is the nbf claim, in UTC. The grant is not valid
	// before this instant.
	NotBefore time.Time

	// ExpiresAt is the exp claim, in UTC. The grant is not valid
	// at or after this instant.
	ExpiresAt time.Time

	// ID is the jti claim — a per-grant unique identifier used by
	// the daemon to revoke individual grants.
	ID string
}

// Sentinel errors for VerifyCapabilityGrant. Callers distinguish
// expired from not-yet-valid for telemetry and from signature failures
// for security alerting.
var (
	// ErrGrantExpired fires when exp <= now.
	ErrGrantExpired = errors.New("authz: capability grant expired")

	// ErrGrantNotYetValid fires when nbf > now.
	ErrGrantNotYetValid = errors.New("authz: capability grant not yet valid")

	// ErrGrantSignature fires for a signature mismatch or unknown
	// kid.
	ErrGrantSignature = errors.New("authz: capability grant signature invalid")

	// ErrGrantMalformed fires for any other parse / structural
	// failure.
	ErrGrantMalformed = errors.New("authz: capability grant malformed")
)
