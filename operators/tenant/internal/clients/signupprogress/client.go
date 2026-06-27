// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package signupprogress is the operator's writer-side client to the
// dashboard's SignupProgressStore — the Redis-backed channel the
// /api/signup/progress/:id polling endpoint reads.
//
// The dashboard's signup-flow extension (spec secrets-tenant-lifecycle
// Requirement 7.2) renders a `provisioning_secrets_backend` step in the
// ProvisioningPanel. That step's progress events are emitted by the
// tenant-operator's saga, NOT by the dashboard server action — by the
// time the action returns the OIDC redirect, the operator is the only
// component still doing work on the tenant's behalf.
//
// Wire shape: keys are `signup-progress:<attemptId>`. Values are JSON
// objects matching the dashboard's ProvisioningProgress type at
// `app/(public)/signup/types.ts`. See the `Progress` struct below for
// the field layout — keep these in sync.
//
// TTL: 5 minutes, matching the dashboard's progress-store TTL. The
// dashboard polls every second; the extra window guarantees the UI can
// render the terminal state before the key expires.
//
// Idempotency: every Publish call is a full SET (with TTL), not an
// incremental update. Re-running on saga retry cleanly overwrites the
// previous value.
package signupprogress

import (
	"context"
	"time"
)

// Step matches the dashboard's `ProvisioningStep` union. The values that
// the operator publishes are limited to those tied to operator-owned
// reconcile steps. Dashboard-owned steps (rate_limit, policy, create_user,
// etc.) stay the dashboard's responsibility.
type Step string

const (
	// StepProvisioningSecretsBackend is published by the
	// ProvisionSecretsBackend saga step while it ensures the per-tenant
	// Vault namespace per Spec 1 R10.3.
	StepProvisioningSecretsBackend Step = "provisioning_secrets_backend"
)

// TerminalState matches the dashboard's `ProvisioningProgress.terminalState`.
type TerminalState string

const (
	// TerminalNone (the empty string) means the step is in flight.
	TerminalNone TerminalState = ""
	// TerminalOK means the step completed successfully.
	TerminalOK TerminalState = "ok"
	// TerminalFailed means the step failed permanently and the dashboard
	// should render a retry CTA.
	TerminalFailed TerminalState = "failed"
)

// FailureCode matches the dashboard's `SignupFailureCode` union. Only
// the codes the operator can produce are listed here. Adding a new code
// requires adding it to the dashboard's union too — they are wire-coupled.
type FailureCode string

const (
	// CodeSecretsNamespaceFailed is surfaced when the operator's
	// VaultProvisioner.EnsureTenantNamespace call has exhausted retries
	// (or hit a permanent error) and the tenant cannot proceed without a
	// secrets backend. Maps to `SECRETS_NAMESPACE_FAILED` on the dashboard.
	CodeSecretsNamespaceFailed FailureCode = "SECRETS_NAMESPACE_FAILED"
)

// ProgressError is the error sub-payload published when terminalState is
// "failed". The fields mirror `ProvisioningProgress.error` on the dashboard.
type ProgressError struct {
	Code        FailureCode `json:"code"`
	UserMessage string      `json:"userMessage"`
}

// Progress is the JSON value written to `signup-progress:<attemptId>`.
// Field tags MUST match the dashboard's TypeScript ProvisioningProgress
// shape so the same JSON round-trips.
type Progress struct {
	Step          Step           `json:"step"`
	StepStartedAt int64          `json:"stepStartedAt"`
	TerminalState TerminalState  `json:"terminalState,omitempty"`
	Error         *ProgressError `json:"error,omitempty"`
}

// Client publishes progress events to the dashboard's SignupProgressStore.
// All methods are no-ops when attemptID is empty — the operator's caller
// reads the attemptID from the Tenant CR's signup-attempt-id annotation
// and falls back to "" when the annotation is absent (e.g., a tenant
// created out-of-band by `kubectl apply` rather than the dashboard's
// signup flow). In that mode the saga still runs end-to-end; only the
// progress publish becomes a no-op.
type Client interface {
	// Advance records that a non-terminal step is in flight. The dashboard's
	// ProvisioningPanel renders a spinner for this state. Idempotent: safe
	// to call on every reconcile of an in-progress step.
	Advance(ctx context.Context, attemptID string, step Step) error

	// Complete records a successful terminal state for a step. The
	// dashboard advances past the rendered step. Idempotent.
	Complete(ctx context.Context, attemptID string, step Step) error

	// Fail records a failed terminal state for a step. The dashboard
	// renders the userMessage with a retry CTA. Idempotent.
	Fail(ctx context.Context, attemptID string, step Step, code FailureCode, userMessage string) error

	// Ping verifies the underlying Redis connection. Used by the operator's
	// readyz check.
	Ping(ctx context.Context) error
}

// Config configures the Redis-backed Client.
type Config struct {
	// Addr is the Redis address (e.g. "redis:6379"). When empty,
	// NewRedisClient returns nil and the operator falls into the
	// degraded-mode no-op path.
	Addr string

	// Password is the optional Redis password.
	Password string

	// DB is the Redis database number (default 0).
	DB int

	// TTL is the value-key TTL. Defaults to 5 minutes to match the
	// dashboard's TTL at app/(public)/signup progress store.
	TTL time.Duration

	// KeyPrefix is the Redis key prefix. Defaults to "signup-progress:".
	// Override only in tests.
	KeyPrefix string
}

// DefaultTTL is the value-key TTL used when Config.TTL is zero. Matches
// the dashboard's PROGRESS_TTL_SECONDS constant exactly.
const DefaultTTL = 5 * time.Minute

// DefaultKeyPrefix is the Redis key prefix used when Config.KeyPrefix
// is empty. Matches the dashboard's PROGRESS_KEY_PREFIX exactly.
const DefaultKeyPrefix = "signup-progress:"
