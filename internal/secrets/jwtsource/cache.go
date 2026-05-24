package jwtsource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var cacheRefreshErrors = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_jwtsource_cache_refresh_errors_total",
		Help: "Total number of background token refresh errors in JWTCache, by audience.",
	},
	[]string{"audience"},
)

// defaultRetryAfter is the interval the background goroutine waits after a
// refresh failure before retrying.
const defaultRetryAfter = 30 * time.Second

// jwtPayload is the minimal JWT payload struct used to extract the expiry claim.
type jwtPayload struct {
	Exp int64 `json:"exp"`
}

// parseExp extracts the exp claim from a JWT string without validating
// the signature. It base64url-decodes the middle segment (the payload)
// and unmarshals the exp field. Returns time.Time{} on any parse error.
func parseExp(token string) time.Time {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var p jwtPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return time.Time{}
	}
	if p.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(p.Exp, 0)
}

// JWTCache wraps a JWTSource and caches the last-fetched token for a fixed
// audience. A background goroutine refreshes the token at half its remaining
// TTL so callers never need to call the underlying source live.
//
// The underlying source is called:
//   - Once synchronously in Start (fail-fast boot)
//   - Periodically by the background goroutine at half remaining TTL
//
// On source failure the goroutine keeps the last-known-good token and retries
// after 30s. The raw token MUST NOT appear in any log or error message.
type JWTCache struct {
	src        JWTSource
	audience   string
	logger     *slog.Logger
	retryAfter time.Duration // how long to wait after a refresh failure

	mu      sync.RWMutex
	token   string
	expiry  time.Time
	started bool

	cancel context.CancelFunc
	done   chan struct{}
}

// NewJWTCache constructs a JWTCache that caches tokens for the given
// audience from src. Call Start before using Token.
func NewJWTCache(src JWTSource, audience string, logger *slog.Logger) *JWTCache {
	return &JWTCache{
		src:        src,
		audience:   audience,
		logger:     logger,
		retryAfter: defaultRetryAfter,
		done:       make(chan struct{}),
	}
}

// Start performs a synchronous first fetch and launches the background
// refresh goroutine. The provided ctx controls the background goroutine
// lifetime; cancel it (or call Close) to stop background work.
//
// Returns an error if the initial fetch fails — this is the fail-fast
// boot path.
func (c *JWTCache) Start(ctx context.Context) error {
	tok, err := c.src.Token(ctx, c.audience)
	if err != nil {
		return fmt.Errorf("jwtsource (cache): initial token fetch for audience=%q: %w", c.audience, err)
	}

	expiry := parseExp(tok)

	bgCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.token = tok
	c.expiry = expiry
	c.started = true
	c.cancel = cancel
	c.mu.Unlock()

	go c.refreshLoop(bgCtx, tok, expiry)
	return nil
}

// refreshLoop is the background goroutine. It wakes at half the remaining
// TTL, refreshes the token, and sleeps again. On source failure it keeps
// the last-known-good token and retries after retryAfter.
func (c *JWTCache) refreshLoop(ctx context.Context, initialToken string, initialExpiry time.Time) {
	defer close(c.done)

	currentToken := initialToken
	currentExpiry := initialExpiry

	for {
		delay := c.nextRefreshDelay(currentExpiry)
		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		tok, err := c.src.Token(ctx, c.audience)
		if err != nil {
			// Keep last-known-good; log a warning with hashed token (never raw).
			hash := sha256.Sum256([]byte(currentToken))
			c.logger.Warn("jwtsource cache: background refresh failed; keeping last-known-good token",
				slog.String("audience", c.audience),
				slog.String("token_sha256", fmt.Sprintf("%x", hash)),
				slog.String("error", err.Error()),
			)
			cacheRefreshErrors.WithLabelValues(c.audience).Inc()

			// Retry after fixed backoff.
			retryTimer := time.NewTimer(c.retryAfter)
			select {
			case <-ctx.Done():
				retryTimer.Stop()
				return
			case <-retryTimer.C:
			}
			// Re-use same currentToken/currentExpiry so next iteration
			// recalculates the delay from the existing expiry.
			continue
		}

		expiry := parseExp(tok)
		c.mu.Lock()
		c.token = tok
		c.expiry = expiry
		c.mu.Unlock()

		currentToken = tok
		currentExpiry = expiry
	}
}

// nextRefreshDelay returns half the remaining time until expiry, with a
// minimum of 1 second to avoid busy-looping on very short-lived tokens.
// If expiry is zero (unparseable), defaults to 30 seconds.
func (c *JWTCache) nextRefreshDelay(expiry time.Time) time.Duration {
	if expiry.IsZero() {
		return 30 * time.Second
	}
	remaining := time.Until(expiry)
	if remaining <= 0 {
		return time.Second
	}
	half := remaining / 2
	if half < time.Second {
		return time.Second
	}
	return half
}

// Token returns the cached token for the given audience. Returns
// ErrJWTSourceDisabled if Start has not been called. Returns an error if
// the requested audience does not match the cache's configured audience.
//
// Token never calls the underlying source — it reads only from the cache
// populated by Start and the background goroutine.
func (c *JWTCache) Token(_ context.Context, audience string) (string, error) {
	c.mu.RLock()
	started := c.started
	tok := c.token
	c.mu.RUnlock()

	if !started {
		return "", ErrJWTSourceDisabled
	}
	if audience != c.audience {
		return "", fmt.Errorf("jwtsource (cache): audience mismatch: requested %q, cache holds %q", audience, c.audience)
	}
	return tok, nil
}

// Close cancels the background goroutine and waits for it to exit.
// Safe to call before Start — it is a no-op in that case.
func (c *JWTCache) Close() error {
	c.mu.RLock()
	cancel := c.cancel
	started := c.started
	c.mu.RUnlock()

	if !started || cancel == nil {
		return nil
	}
	cancel()
	<-c.done
	return nil
}
