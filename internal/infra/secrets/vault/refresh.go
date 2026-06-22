package vault

// refresh.go — Vault token refresh helper.
//
// RefreshToken performs a Vault re-authentication and returns a fresh
// ClientToken and its LeaseDuration. It is the single implementation behind
// the daemon's AuthRefreshFn closure at broker_init.go.
//
// Security invariant: the raw token string MUST NOT appear in any error
// message, log field, or struct field returned from this file. Only the
// caller — the daemon closure — hashes and logs the token.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// ErrVaultRefreshNoAuth is returned by RefreshToken when the Vault login
// call succeeds at the network level but returns a nil Auth block, meaning
// Vault acknowledged the request but produced no credential. This usually
// indicates a Vault policy or method misconfiguration rather than a
// transient network error.
//
// Callers MUST NOT retry indefinitely on this error.
var ErrVaultRefreshNoAuth = fmt.Errorf("vault refresh: login succeeded but returned no auth credential")

// VaultRefreshError wraps a Vault authentication failure that occurs during
// token refresh. It carries the TenantID and the auth Method for operator
// diagnostics without including the token itself.
//
// VaultRefreshError implements Unwrap() so errors.Is / errors.As traversal
// reaches the underlying Cause.
type VaultRefreshError struct {
	// TenantID identifies the tenant whose token refresh failed.
	// Never contains the token.
	TenantID string

	// Method is the Vault auth method that was attempted.
	Method AuthMethod

	// Cause is the underlying error from the auth call or config parsing.
	Cause error
}

// Error implements the error interface.
// The token string MUST NOT appear in this message.
func (e *VaultRefreshError) Error() string {
	if e.Method != "" {
		return fmt.Sprintf("vault refresh failed for tenant %q using method %q: %v", e.TenantID, e.Method, e.Cause)
	}
	return fmt.Sprintf("vault refresh failed for tenant %q: %v", e.TenantID, e.Cause)
}

// Unwrap returns the underlying Cause so errors.Is / errors.As traversal
// reaches it.
func (e *VaultRefreshError) Unwrap() error {
	return e.Cause
}

// RefreshToken authenticates to Vault using cfg and returns the fresh
// ClientToken string, the token's LeaseDuration (full issued TTL), and any
// error.
//
// It reuses authenticate() from auth.go — the same code path as New() — to
// perform the login, then calls the Vault token lookup-self endpoint to
// retrieve the token's TTL.
//
// On success the caller receives:
//   - token: an opaque token string suitable for client.SetToken. MUST be
//     treated as a secret — never logged directly.
//   - ttl: the full issued lifetime of the token as reported by Vault.
//     Callers typically apply an 80% fraction (AuthCache does this internally).
//     A zero ttl means Vault returned no expiration (e.g. static root tokens).
//
// RefreshToken returns ErrVaultRefreshNoAuth when the Vault login call
// produces no Auth block. It returns a *VaultRefreshError on all other
// auth failures so callers can type-assert for structured error handling.
//
// The raw token string MUST NOT appear in any returned error.
func RefreshToken(ctx context.Context, cfg Config) (token string, ttl time.Duration, err error) {
	if cfg.Address == "" {
		return "", 0, &VaultRefreshError{
			Method: cfg.Auth.Method,
			Cause:  fmt.Errorf("vault: Config.Address is required"),
		}
	}

	// Build an auth-only client. We skip the KV version check (detectKVVersion)
	// because this function only performs authentication, not KV operations.
	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = cfg.Address
	vaultCfg.Timeout = 15 * time.Second

	client, clientErr := api.NewClient(vaultCfg)
	if clientErr != nil {
		return "", 0, &VaultRefreshError{
			Method: cfg.Auth.Method,
			Cause:  fmt.Errorf("vault: failed to create client: %w", clientErr),
		}
	}

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// Perform the auth login using the same authenticate() logic as New().
	// On return, the fresh token is stored on client via client.SetToken.
	if authErr := authenticate(ctx, client, cfg.Auth); authErr != nil {
		return "", 0, &VaultRefreshError{
			Method: cfg.Auth.Method,
			Cause:  authErr,
		}
	}

	// Read the token from the client. authenticate() calls client.SetToken
	// for all auth methods.
	freshToken := client.Token()
	if freshToken == "" {
		// authenticate() should not succeed and leave an empty token, but
		// guard against this to avoid returning an unusable credential.
		return "", 0, ErrVaultRefreshNoAuth
	}

	// For token-method auth, Vault does not issue a TTL — the token is
	// static. Return zero TTL; the AuthCache will apply a safe default.
	if cfg.Auth.Method == AuthMethodToken {
		return freshToken, 0, nil
	}

	// For dynamic auth methods (AppRole, K8s, JWT, AWSIAM), query the
	// token lookup-self endpoint to retrieve the TTL of the newly issued
	// token. This is the canonical way to discover a token's remaining
	// lifetime without relying on the in-memory auth response object (which
	// authenticate() does not surface to callers).
	//
	// A lookup failure is non-fatal: we have a valid token but an unknown
	// TTL. Return with ttl=0; the AuthCache applies its safe default (5m).
	secret, lookupErr := client.Auth().Token().LookupSelfWithContext(ctx)
	if lookupErr != nil || secret == nil || secret.Data == nil {
		return freshToken, 0, nil //nolint:nilerr // lookup failure is non-fatal; token is valid but TTL unknown — return zero TTL so AuthCache uses its safe default
	}

	// Extract the TTL from the lookup response. The Vault API decodes JSON
	// numbers as json.Number or float64 depending on the decoder used by
	// the SDK. Handle both common representations.
	ttl = extractTTL(secret.Data)
	return freshToken, ttl, nil
}

// extractTTL reads the "ttl" field from a Vault token lookup-self response
// data map and returns it as a time.Duration. Returns 0 if the field is
// absent or cannot be converted.
//
// The Vault SDK decodes responses with UseNumber(), so numeric fields arrive
// as json.Number rather than float64. We handle both for robustness.
func extractTTL(data map[string]interface{}) time.Duration {
	raw, ok := data["ttl"]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case json.Number:
		if f, err := v.Float64(); err == nil && f > 0 {
			return time.Duration(f) * time.Second
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case int64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return 0
}
