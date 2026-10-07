// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets/jwtsource"
)

// stampVaultJWTOnConfig mints a SPIRE JWT-SVID via src and writes it onto
// cfg.Auth.JWT when the broker config selects AuthMethodJWT but carries
// no static JWT.
//
// Why this exists (ADR-0009 + amendment docs#34): the tenant-operator
// writes per-tenant broker configs that reference a Vault auth/jwt role
// (gibson-plugin-<tenant_id>) but never the bearer JWT itself — the
// JWT must be minted by the daemon, per request, from the daemon's own
// SPIRE identity. This helper is the single point at which that mint
// happens, before any sdkvault call. Both the AuthCache refresh closure
// (broker_init.go) and the direct-auth fallback in the Vault factory
// (broker_init.go) call it.
//
// Behaviour matrix:
//
//   - cfg.Auth.Method != AuthMethodJWT → no-op (returns nil, cfg unchanged).
//   - cfg.Auth.Method == AuthMethodJWT AND cfg.Auth.JWT != "" → no-op
//     (caller-supplied JWTs win; allows local-dev short-circuit and
//     migration scenarios without touching this code path).
//   - cfg.Auth.Method == AuthMethodJWT AND cfg.Auth.JWT == "" AND src is
//     nil OR audience is "" → error. Fail-loud: AuthMethodJWT without a
//     JWTSource + audience is a misconfiguration the daemon must surface
//     rather than silently fall back to a non-JWT method.
//   - Otherwise → call src.Token(ctx, audience); on success, write the
//     returned token onto cfg.Auth.JWT and return nil.
//
// The returned JWT MUST NOT be logged by this helper or any caller.
// Spec: ADR-0009 amendment (docs#34); gibson#167 PRD; gibson#168.
func stampVaultJWTOnConfig(ctx context.Context, cfg *sdkvault.Config, src jwtsource.JWTSource, audience string) error {
	if cfg == nil {
		return fmt.Errorf("stamp jwt: nil config")
	}
	if cfg.Auth.Method != sdkvault.AuthMethodJWT {
		return nil
	}
	if cfg.Auth.JWT != "" {
		// Caller already supplied a JWT (local-dev short-circuit / test).
		return nil
	}
	if src == nil {
		return fmt.Errorf("stamp jwt: AuthMethodJWT requires a JWTSource but none was wired (set WithVaultJWTSource in daemon.New; spec: gibson#168)")
	}
	if audience == "" {
		return fmt.Errorf("stamp jwt: AuthMethodJWT requires a non-empty audience (set GIBSON_DAEMON_VAULT_JWT_AUDIENCE in the daemon env; spec: gibson#168)")
	}
	tok, err := src.Token(ctx, audience)
	if err != nil {
		return fmt.Errorf("stamp jwt: mint token for audience %q: %w", audience, err)
	}
	if tok == "" {
		return fmt.Errorf("stamp jwt: source returned an empty JWT for audience %q", audience)
	}
	cfg.Auth.JWT = tok
	return nil
}

// vaultConfigCacheKey returns a stable, opaque cache key for an sdkvault.Config
// blob. The key is a SHA-256 hex digest of the canonicalized JSON
// representation; identical configs (Address + Namespace + Auth fields) hash
// to the same key, distinct configs do not collide.
//
// This key is used as the AuthCache's "tenant" parameter so that callers
// without a TenantID handy (e.g. the registry's blob-only factory) still get
// per-config singleflight protection.
func vaultConfigCacheKey(blob []byte) string {
	h := sha256.Sum256(blob)
	return "vaultcfg:" + hex.EncodeToString(h[:8]) // 16 hex chars is plenty for log readability
}

// vaultRefreshLookup is a process-wide map of cache key → sdkvault.Config.
// Populated by makeVaultFactory before each GetOrRefresh, consumed by the
// AuthRefreshFn closure. The AuthRefreshFn cannot reach the config any other
// way because secrets.AuthRefreshFn only carries opaque (tenant, provider)
// strings.
//
// A sync.Map suffices: writes are far less frequent than reads, and even
// after a write/read race the worst case is a single missed cache lookup,
// which the singleflight handles.
type vaultRefreshLookup struct {
	mu      sync.RWMutex
	configs map[string]sdkvault.Config
}

func newVaultRefreshLookup() *vaultRefreshLookup {
	return &vaultRefreshLookup{configs: make(map[string]sdkvault.Config)}
}

func (l *vaultRefreshLookup) put(key string, cfg sdkvault.Config) {
	l.mu.Lock()
	l.configs[key] = cfg
	l.mu.Unlock()
}

func (l *vaultRefreshLookup) get(key string) (sdkvault.Config, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c, ok := l.configs[key]
	return c, ok
}
