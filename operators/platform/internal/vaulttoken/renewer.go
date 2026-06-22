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

// Renewer holds a Vault admin token and keeps it alive via background renewal.
type Renewer struct {
	token  string
	mu     sync.RWMutex
	renErr error
	cancel context.CancelFunc
	done   chan struct{}
}

// New constructs a Renewer. One of token or tokenPath must be non-empty.
// The background renewal goroutine starts immediately and runs until Close
// is called or ctx is cancelled.
func New(ctx context.Context, address, token, tokenPath string) (*Renewer, error) {
	if address == "" {
		return nil, errors.New("vaulttoken.New: address required")
	}
	if token == "" && tokenPath == "" {
		return nil, errors.New("vaulttoken.New: token or tokenPath required")
	}
	resolved := token
	if resolved == "" {
		raw, err := os.ReadFile(tokenPath) //nolint:gosec // path comes from VAULT_TOKEN_PATH env var set by the Helm chart
		if err != nil {
			return nil, fmt.Errorf("vaulttoken.New: read token file %q: %w", tokenPath, err)
		}
		resolved = strings.TrimSpace(string(raw))
		if resolved == "" {
			return nil, fmt.Errorf("vaulttoken.New: token file %q is empty", tokenPath)
		}
	}

	cfg := vaultapi.DefaultConfig()
	cfg.Address = address
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vaulttoken.New: create vault client: %w", err)
	}
	client.SetToken(resolved)

	// Look up the token's TTL to determine the renewal interval. A TTL of 0
	// means the token is a root token or explicitly non-renewable; skip the
	// renewal loop in that case. Lookup failure is non-fatal — we still have a
	// valid token; skip renewal conservatively.
	interval, _ := lookupRenewInterval(ctx, client)

	renewCtx, cancel := context.WithCancel(ctx)
	r := &Renewer{
		token:  resolved,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go r.renewLoop(renewCtx, client, interval)
	return r, nil
}

// Token returns the admin token, or an error if the last renewal attempt
// failed. Callers should treat a non-nil error as transient and requeue.
func (r *Renewer) Token() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.renErr != nil {
		return "", fmt.Errorf("vault admin token renewal failed: %w", r.renErr)
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

func (r *Renewer) renewLoop(ctx context.Context, client *vaultapi.Client, interval time.Duration) {
	defer close(r.done)
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
