// Package entitlements is the pluggable seam that decouples commercial
// gating from the OSS brain (docs ADR-0003, CONTEXT.md "Entitlements
// provider").
//
// The budget enforcer (internal/budget) and the concurrency rate limiter
// (internal/component QuotaManager) consume "what are this tenant's limits
// / what's enabled?" exclusively through the Provider interface. They never
// read plans or Stripe directly. This package therefore holds NO plan
// model, NO Stripe types, and NO billing knowledge — it is part of OSS
// gibson.
//
//   - OSS (this package, DefaultProvider) ships a permissive/config-driven
//     provider: limits come from admin-set quota config (the platform
//     tenant_quotas row), and absence means unlimited. No payment.
//   - Commercial layer (out-of-repo, lands via gibson#798 once the E4
//     monorepo exists) ships a provider that derives Limits from the plan +
//     subscription (Stripe) state. It satisfies this same interface, so the
//     OSS runtime never changes when the commercial provider is swapped in.
//
// BillingService, Stripe, and plans.yaml live entirely in the commercial
// layer — never behind this seam.
package entitlements

import (
	"context"
	"database/sql"
)

// Limits is the plan-agnostic set of resource ceilings the runtime enforces
// for one tenant. A zero value on any field means "unlimited on that
// dimension" — callers interpret absence as no enforcement. The struct
// carries no plan name, tier, or payment state: the Provider has already
// reduced whatever upstream policy applies (admin config for OSS, plan +
// subscription for commercial) to bare numbers the OSS enforcers act on.
type Limits struct {
	// ConcurrentMissions caps simultaneously-running missions. 0 = unlimited.
	ConcurrentMissions int

	// ConcurrentAgents caps agents bound to in-flight tasks. 0 = unlimited.
	ConcurrentAgents int

	// ConcurrentConnectors caps running hosted MCP connector instances.
	// 0 = unlimited.
	ConcurrentConnectors int

	// MonthlyTokens is the per-tenant default token ceiling per billing
	// period, consumed by the budget enforcer as the tenant-scope default
	// when no explicit admin-set tenant budget exists. 0 = unlimited.
	MonthlyTokens int64

	// MonthlySpendUSDCents is the per-tenant default LLM-spend ceiling per
	// billing period, in USD cents. 0 = unlimited.
	MonthlySpendUSDCents int64
}

// Provider answers "what are this tenant's limits / what's enabled?" for the
// OSS runtime enforcers. Implementations must be safe for concurrent use.
//
// Limits returns the tenant's resource ceilings. A provider that has no
// configured limits for a tenant returns the zero Limits value (every
// dimension unlimited) — never an error — so the runtime fails open rather
// than blocking on an unconfigured or absent backing store. Errors are
// reserved for genuine backend failures the caller may choose to log; even
// then callers treat the result as unlimited (fail-open), matching the
// pre-seam QuotaManager behaviour.
type Provider interface {
	// Limits returns the resource ceilings for tenantID. The zero Limits
	// value means unlimited on every dimension.
	Limits(ctx context.Context, tenantID string) (Limits, error)
}

// UnlimitedProvider is the most permissive Provider: every tenant gets
// unlimited everything. It is the right default for a single-team self-host
// that does not want any concurrency caps, and the safe fallback wherever a
// Provider is required but none is configured (nil Provider).
type UnlimitedProvider struct{}

// Limits always returns the zero (unlimited) Limits value.
func (UnlimitedProvider) Limits(context.Context, string) (Limits, error) {
	return Limits{}, nil
}

// Resolve returns p when non-nil, else an UnlimitedProvider. Wiring code
// uses this so a nil Provider degrades to fail-open rather than panicking.
func Resolve(p Provider) Provider {
	if p == nil {
		return UnlimitedProvider{}
	}
	return p
}

// factory, when installed via Register, overrides the OSS default in New.
// It takes the daemon's platform DB handle so a provider that needs it (the
// OSS default does) can use it; a provider that needs more (the commercial
// Stripe-backed one needs a Stripe client + plan registry) captures those in
// the closure it registers.
var factory func(db *sql.DB) Provider

// Register installs the Provider factory the commercial billing layer supplies
// (gibson#798/#800). The closed module calls it once at startup — typically
// from an init() that a hosted daemon build imports for its side effect — so
// that New returns the Stripe-backed provider instead of the OSS default. OSS
// gibson never calls Register, so the seam stays open-core: the default path
// has zero knowledge of plans or Stripe. Last call wins; not safe for
// concurrent use with New (call it during single-threaded startup wiring).
func Register(f func(db *sql.DB) Provider) { factory = f }

// New is the single Entitlements injection point. It returns the registered
// commercial provider when one was installed via Register, else the OSS
// config-driven default (NewConfigProvider). Daemon wiring calls New — never
// NewConfigProvider directly — so the commercial provider drops in with no
// daemon change.
func New(db *sql.DB) Provider {
	if factory != nil {
		return factory(db)
	}
	return NewConfigProvider(db)
}
