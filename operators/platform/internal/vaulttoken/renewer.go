// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
//
// Verify-retry design (fixes gibson#1173):
//   - The very first LookupSelf (used only to determine the renewal
//     interval) used to be a single fire-and-forget attempt: a failure was
//     swallowed and treated identically to "non-renewable", which
//     permanently exited the background goroutine WITHOUT setting renErr.
//     On a cold bringup where this process's tokenPath read raced OpenBao
//     writing the real admin token (acquiring a stale placeholder), that
//     froze Token() on the bad value forever, with no error surfaced and no
//     further attempt made — only a full pod restart (which re-runs the
//     acquire phase against the by-then-corrected file) recovered.
//   - LookupSelf failures are now retried indefinitely (backoff at
//     minRenewInterval) via waitForVerifiedToken, which re-reads tokenPath
//     on every attempt so a token corrected on disk is used instead of the
//     stale in-memory copy. The same re-read happens on every RenewSelf
//     retry inside renewLoop, closing the same class of bug for a token
//     that goes bad mid-life (e.g. revoked, then rotated) rather than only
//     at initial acquisition.
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

// retryBackoff is how long waitForVerifiedToken and renewLoop wait before
// retrying a failed LookupSelf/RenewSelf attempt. Defaults to
// minRenewInterval; a var (distinct from the clampInterval floor) so tests
// can shorten it without changing renewal-cadence semantics. gibson#1173.
var retryBackoff = minRenewInterval

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

	// Verify the token and look up its TTL to determine the renewal
	// interval. A TTL of 0 means the token is a root token or explicitly
	// non-renewable; the renewal loop is a no-op in that case. A LookupSelf
	// failure (e.g. the token acquired above was rejected by Vault) is
	// retried indefinitely rather than silently giving up — see
	// waitForVerifiedToken.
	interval := r.waitForVerifiedToken(ctx, client, tokenPath)
	if interval < 0 {
		return // ctx cancelled while verifying
	}
	r.renewLoop(ctx, client, interval, tokenPath)
}

// waitForVerifiedToken calls LookupSelf until it succeeds or ctx is
// cancelled. Every failed attempt sets r.renErr (surfaced to callers via
// Token()) and re-reads tokenPath before retrying, so a token that was
// corrected on disk after this process cached it — e.g. because it lost a
// race against OpenBao writing the real admin token on a cold bringup — is
// picked up without a pod restart (gibson#1173). Returns the renewal
// interval (0 for a confirmed non-renewable token) on success, or -1 if ctx
// was cancelled first.
func (r *Renewer) waitForVerifiedToken(ctx context.Context, client *vaultapi.Client, tokenPath string) time.Duration {
	for {
		interval, err := lookupRenewInterval(ctx, client)
		if err == nil {
			r.mu.Lock()
			r.renErr = nil
			r.mu.Unlock()
			return interval
		}
		if ctx.Err() != nil {
			return -1
		}
		r.mu.Lock()
		r.renErr = fmt.Errorf("vaulttoken: verify token: %w", err)
		r.mu.Unlock()

		select {
		case <-ctx.Done():
			return -1
		case <-time.After(retryBackoff):
		}

		if tokenPath != "" {
			if fresh := resolveToken("", tokenPath); fresh != "" {
				r.mu.Lock()
				r.token = fresh
				r.mu.Unlock()
				client.SetToken(fresh)
			}
		}
	}
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
//
// tokenPath, if non-empty, is re-read whenever RenewSelf fails (gibson#1173):
// a renewal failure may mean the CACHED token itself has gone bad (revoked,
// rotated) rather than a transient network blip, so retrying blindly against
// the same in-memory token forever would repeat the cold-bringup bug at a
// later point in the process lifetime. Re-reading picks up a corrected token
// without a pod restart. A literal VAULT_TOKEN override (tokenPath == "") is
// immutable for the process lifetime, so the re-read is a no-op in that mode.
func (r *Renewer) renewLoop(ctx context.Context, client *vaultapi.Client, interval time.Duration, tokenPath string) {
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
				interval = retryBackoff // back off and retry
				if tokenPath != "" {
					if fresh := resolveToken("", tokenPath); fresh != "" {
						r.mu.Lock()
						r.token = fresh
						r.mu.Unlock()
						client.SetToken(fresh)
					}
				}
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
