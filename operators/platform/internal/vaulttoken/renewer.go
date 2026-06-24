// Package vaulttoken provides a Vault admin token source for the
// platform-operator. It resolves the token from an env var or a file path
// and runs a background goroutine that calls Vault's renew-self endpoint
// before the token TTL expires, keeping the token alive for the lifetime
// of the process.
//
// Renewal design (closes platform-operator#61):
//   - At construction, LookupSelf fetches the token's TTL.
//   - The background goroutine sleeps for 2/3 of the TTL (clamped to
//     [30s, 10m]) then calls RenewSelf. On success the interval is updated
//     from the returned lease duration; on failure renewErr is set.
//   - Token() returns an error when renewErr is non-nil; callers requeue.
//   - Close() cancels the background goroutine and waits for it to exit.
//   - Tokens with TTL == 0 (root tokens, non-renewable) skip the loop;
//     Token() always succeeds for them.
package vaulttoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/openbao/openbao/api/v2"
)

const (
	minRenewInterval = 30 * time.Second
	maxRenewInterval = 10 * time.Minute
)

// acquirePollInterval is how often run() re-reads tokenPath while waiting for
// the admin token to first appear (e.g. OpenBao has not yet minted/written it
// on a from-zero bringup). A var so tests can shorten it. deploy#971.
var acquirePollInterval = 5 * time.Second

// Renewer holds a Vault admin token and keeps it alive via background renewal.
type Renewer struct {
	token  string
	mu     sync.RWMutex
	renErr error
	cancel context.CancelFunc
	done   chan struct{}
}

// New constructs a Renewer. One of token or tokenPath must be CONFIGURED
// (non-empty), but the token VALUE need not be available yet: on a from-zero
// bringup the OpenBao admin token Secret may not exist when the operator
// starts, because OpenBao mints/writes it later in the sync order (deploy#971).
// Rather than fail startup (which crash-loops the pod and deadlocks Argo —
// gibson-operators never goes Healthy, so the wave that brings up OpenBao never
// runs), New always succeeds when a source is configured: it starts a
// background goroutine that acquires the token (polling tokenPath, a
// kubelet-refreshed projected Secret) and then keeps it renewed. Until the
// token is acquired, Token() returns a transient error, which the
// PlatformBootstrap reconciler already treats as a requeue — the idiomatic
// controller pattern for a not-yet-ready dependency.
func New(ctx context.Context, address, token, tokenPath string) (*Renewer, error) {
	if address == "" {
		return nil, errors.New("vaulttoken.New: address required")
	}
	if token == "" && tokenPath == "" {
		return nil, errors.New("vaulttoken.New: token or tokenPath required")
	}

	renewCtx, cancel := context.WithCancel(ctx)
	r := &Renewer{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	// Fast path: if the token is already available (env override, or the
	// projected file exists), store it synchronously so Token() works
	// immediately. Otherwise run() polls until it appears.
	if resolved := resolveToken(token, tokenPath); resolved != "" {
		r.token = resolved
	}
	go r.run(renewCtx, address, tokenPath)
	return r, nil
}

// resolveToken returns the literal token if set, else the trimmed contents of
// tokenPath if it exists and is non-empty, else "" (not yet available).
func resolveToken(token, tokenPath string) string {
	if t := strings.TrimSpace(token); t != "" {
		return t
	}
	if tokenPath != "" {
		if raw, err := os.ReadFile(tokenPath); err == nil { //nolint:gosec // path comes from VAULT_TOKEN_PATH env var set by the Helm chart
			return strings.TrimSpace(string(raw))
		}
	}
	return ""
}

// run acquires the admin token (tolerating it not existing yet) and then keeps
// it renewed for the lifetime of ctx. It owns closing r.done.
func (r *Renewer) run(ctx context.Context, address, tokenPath string) {
	defer close(r.done)

	// Acquire phase. If New already resolved a token, this returns at once.
	r.mu.RLock()
	resolved := r.token
	r.mu.RUnlock()
	for resolved == "" {
		select {
		case <-ctx.Done():
			return
		case <-time.After(acquirePollInterval):
		}
		if resolved = resolveToken("", tokenPath); resolved != "" {
			r.mu.Lock()
			r.token = resolved
			r.mu.Unlock()
		}
	}

	// Renewal phase.
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		r.mu.Lock()
		r.renErr = fmt.Errorf("vaulttoken: create vault client: %w", err)
		r.mu.Unlock()
		return
	}
	client.SetToken(resolved)

	// Look up the token's TTL to determine the renewal interval. A TTL of 0
	// means the token is a root token or explicitly non-renewable; skip the
	// renewal loop in that case. Lookup failure is non-fatal — we still have a
	// valid token; skip renewal conservatively.
	interval, _ := lookupRenewInterval(ctx, client)
	r.renewLoop(ctx, client, interval)
}

// Token returns the admin token, or an error if it is not yet available or the
// last renewal attempt failed. Callers should treat a non-nil error as
// transient and requeue.
func (r *Renewer) Token() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.renErr != nil {
		return "", fmt.Errorf("vault admin token renewal failed: %w", r.renErr)
	}
	if r.token == "" {
		return "", errors.New("vault admin token not yet available (waiting for OpenBao to mint/write it)")
	}
	return r.token, nil
}

// Close stops the background renewal goroutine and waits for it to exit.
// Idempotent.
func (r *Renewer) Close() error {
	r.cancel()
	<-r.done
	return nil
}

// renewLoop keeps the token renewed. It does NOT close r.done — its caller
// (run) owns the goroutine lifetime.
func (r *Renewer) renewLoop(ctx context.Context, client *vaultapi.Client, interval time.Duration) {
	if interval == 0 {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			secret, err := client.Auth().Token().RenewSelfWithContext(ctx, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				r.mu.Lock()
				r.renErr = err
				r.mu.Unlock()
				interval = minRenewInterval // back off and retry
				continue
			}
			r.mu.Lock()
			r.renErr = nil
			r.mu.Unlock()
			if secret != nil && secret.Auth != nil && secret.Auth.LeaseDuration > 0 {
				interval = clampInterval(time.Duration(secret.Auth.LeaseDuration) * time.Second * 2 / 3)
			}
		}
	}
}

// lookupRenewInterval calls LookupSelf to determine the renewal interval.
// Returns 0 for non-renewable tokens or when the TTL is unavailable.
func lookupRenewInterval(ctx context.Context, client *vaultapi.Client) (time.Duration, error) {
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("vaulttoken: lookup-self: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return 0, nil
	}
	renewable, _ := secret.Data["renewable"].(bool)
	if !renewable {
		return 0, nil
	}
	ttlRaw, ok := secret.Data["ttl"]
	if !ok {
		return 0, nil
	}
	var ttlSecs int64
	switch v := ttlRaw.(type) {
	case float64:
		ttlSecs = int64(v)
	case int64:
		ttlSecs = v
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("vaulttoken: ttl parse: %w", err)
		}
		ttlSecs = n
	default:
		return 0, nil
	}
	if ttlSecs <= 0 {
		return 0, nil
	}
	return clampInterval(time.Duration(ttlSecs) * time.Second * 2 / 3), nil
}

func clampInterval(d time.Duration) time.Duration {
	if d < minRenewInterval {
		return minRenewInterval
	}
	if d > maxRenewInterval {
		return maxRenewInterval
	}
	return d
}
