// Package entitlements is the pluggable seam that decouples commercial
// gating from the OSS brain (docs ADR-0003, CONTEXT.md "Entitlements
// provider").
//
// The budget enforcer (internal/platform/budget) and the concurrency rate
// limiter (internal/platform/component QuotaManager) consume "what are this
// tenant's limits / what's enabled?" exclusively through the Provider
// interface. They never read plans or Stripe directly. This package therefore
// holds NO plan model, NO Stripe types, and NO billing knowledge — it is part
// of OSS gibson.
//
// It lives under pkg/ (not internal/) so the closed commercial billing repo
// can import the Provider interface and the generated gRPC stubs at
// pkg/billing/entitlements/v1 to implement the server side without violating
// Go's internal/ import restriction.
//
// Runtime seam (ADR-0003 / ADR-0054 / gibson#1026 / gibson#1028 / gibson#1087):
//
//   - When ENTITLEMENTS_ENDPOINT is set (hosted daemon build), New returns a
//     caching gRPC client that calls the closed billing service's
//     EntitlementsService over SPIFFE mTLS. The billing service derives limits
//     from the tenant's plan + subscription state.
//   - When ENTITLEMENTS_ENDPOINT is unset (OSS / self-hosted), New returns the
//     OSS config-driven default (ConfigProvider): limits come from admin-set
//     quota config (the platform tenant_quotas row), and absence means
//     unlimited. No payment.
//
// BillingService, Stripe, and plans.yaml live entirely in the commercial
// layer — never behind this seam.
//
// The resolution logic is implemented using the reusable [pkg/seam] primitive
// (deploy ADR-0006, gibson#1087) so the knob-set/fail-safe semantics and the
// observable degradation signals are consistent across all seams.
package entitlements

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"strings"

	"github.com/zeroroot-ai/gibson/pkg/seam"
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

// SeamName is the canonical seam identifier for entitlements. It is used
// when registering the seam in the process-wide seam registry so the startup
// seam-state log can reference it by name.
const SeamName = "entitlements"

// SeamKnob is the env-var name whose non-empty value activates the remote
// billing/entitlements-svc implementation.
const SeamKnob = "ENTITLEMENTS_ENDPOINT"

func init() {
	// Register the entitlements seam in the process-wide seam registry so it
	// appears in the daemon's startup seam-state log (deploy ADR-0006,
	// gibson#1087).
	seam.Register(SeamName, SeamKnob, "billing/entitlements-svc")
}

// New is the single Entitlements injection point.
//
// When ENTITLEMENTS_ENDPOINT is set it returns a caching gRPC-client Provider
// that calls the commercial EntitlementsService over SPIFFE mTLS (Option B,
// gibson#1028). The billing service's SPIFFE ID is read from
// ENTITLEMENTS_BILLING_SVID (defaults to permissive AuthorizeAny when unset —
// tighten in production by setting the full "spiffe://…" SVID). The SPIRE
// Workload API socket is read from SPIFFE_ENDPOINT_SOCKET (the go-spiffe
// conventional env var; the chart mounts it via CSI).
//
// When ENTITLEMENTS_ENDPOINT is unset it returns the OSS config-driven default
// (NewConfigProvider). Daemon wiring calls New — never NewConfigProvider
// directly — so the gRPC backend activates with a single env var change and
// no daemon code change.
//
// The resolution is implemented on top of the reusable [pkg/seam] primitive
// (deploy ADR-0006, gibson#1087) — the same knob-set→remote / knob-absent→
// fail-safe / fail-safe-emits-observable semantics apply to all seams.
func New(db *sql.DB) Provider {
	s := seam.New(seam.Spec[Provider]{
		Name:       SeamName,
		ConfigKnob: SeamKnob,
		FailSafe: func() (Provider, error) {
			return NewConfigProvider(db), nil
		},
		Remote: func(endpoint string) (Provider, error) {
			return NewGRPCProvider(GRPCProviderOptions{
				Endpoint:           endpoint,
				BillingServiceSVID: strings.TrimSpace(os.Getenv("ENTITLEMENTS_BILLING_SVID")),
				// WorkloadAPISocket defaults to "" → go-spiffe reads SPIFFE_ENDPOINT_SOCKET.
			})
		},
	})

	// We use slog.Default() directly here because New is called during daemon
	// startup before the daemon's own logger is wired; slog is always initialised
	// by the time daemon.Start() runs.
	res, err := s.Resolve(context.Background(), slog.Default())
	if err != nil {
		// FailSafe returned an error — this should not happen for entitlements
		// (NewConfigProvider never fails). Fall back to unlimited to keep the
		// daemon bootable.
		slog.Default().Error(
			"entitlements: fail-safe construction failed; using UnlimitedProvider",
			"error", err,
		)
		return UnlimitedProvider{}
	}
	return res.Impl
}
