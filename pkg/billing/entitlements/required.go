package entitlements

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
)

// RequiredKnob is the env-var name that declares "entitlements are required
// here; never fall open to unlimited." When set to "true" (case-insensitive)
// the daemon operates in SaaS mode: any failure to obtain entitlements — a
// missing endpoint, a failed remote construction, or a per-call RPC error —
// resolves to a fail-closed (blocked) posture rather than the OSS default of
// fail-open unlimited.
//
// OSS / self-hosted: leave unset (or set to any value other than "true").
// SaaS overlay: set GIBSON_ENTITLEMENTS_REQUIRED=true (deploy#1055).
//
// This knob obeys the same deploy-time-only discipline as ENTITLEMENTS_ENDPOINT:
// it is read once at boot from the process environment; no request can mutate
// it at runtime (Invariant 1 of the security assessment, gibson#1093).
const RequiredKnob = "GIBSON_ENTITLEMENTS_REQUIRED"

// ErrEntitlementsRequired is returned by the BlockedProvider and by the
// gRPC provider (in SaaS mode) when a Limits call cannot be served. It is a
// sentinel the enforcement layer (quota.go, budget enforcer) recognises to
// distinguish "entitlements unavailable in SaaS mode → deny" from "provider
// returned no limits → unlimited."
//
// Callers that receive this error MUST deny the operation rather than
// failing open. See [IsRequired].
var ErrEntitlementsRequired = errors.New("entitlements: entitlements are required but unavailable; denying (SaaS fail-closed)")

// IsRequired reports whether err (or any error it wraps) is
// [ErrEntitlementsRequired]. Enforcement code uses this to distinguish the
// SaaS fail-closed signal from generic transient backend errors.
func IsRequired(err error) bool {
	return errors.Is(err, ErrEntitlementsRequired)
}

// Required reports whether GIBSON_ENTITLEMENTS_REQUIRED is set to "true"
// (case-insensitive) in the current process environment. It reads the env var
// on every call so tests that use t.Setenv get consistent results; the daemon
// calls it once at boot via [New] and caches the result there.
func Required() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(RequiredKnob)), "true")
}

// BlockedProvider is a Provider that always denies by returning
// [ErrEntitlementsRequired]. It is installed when GIBSON_ENTITLEMENTS_REQUIRED
// is true and the entitlements seam cannot be wired (endpoint absent or remote
// construction failed). The enforcement layer interprets [ErrEntitlementsRequired]
// as "deny" rather than "unlimited," satisfying Invariants 3 and 4.
//
// This is the SaaS boot guard: deploying with GIBSON_ENTITLEMENTS_REQUIRED=true
// but without ENTITLEMENTS_ENDPOINT (or with a broken SPIRE wiring) means the
// daemon starts but every entitlements check is denied — so no tenant can run
// any mission, agent, or connector. Operators see the boot log warning and the
// denied requests until the misconfiguration is fixed.
type BlockedProvider struct {
	logger *slog.Logger
}

// NewBlockedProvider returns a BlockedProvider that logs every denied call.
// logger may be nil; slog.Default() is used in that case.
func NewBlockedProvider(logger *slog.Logger) *BlockedProvider {
	if logger == nil {
		logger = slog.Default()
	}
	return &BlockedProvider{logger: logger}
}

// Limits always returns [ErrEntitlementsRequired]. Enforcement callers that
// check [IsRequired] will deny the operation; the zero Limits value is
// meaningless in the error case and must not be used.
func (b *BlockedProvider) Limits(_ context.Context, tenantID string) (Limits, error) {
	b.logger.Warn(
		"entitlements: blocked provider active — SaaS entitlements required but unavailable; denying",
		"tenant", tenantID,
	)
	return Limits{}, ErrEntitlementsRequired
}
