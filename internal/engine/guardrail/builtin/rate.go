package builtin

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
)

// RateLimiterConfig configures the rate limiter
type RateLimiterConfig struct {
	MaxRequests int           // Max requests per window
	Window      time.Duration // Time window
	BurstSize   int           // Burst capacity (defaults to MaxRequests)
	PerTarget   bool          // Separate limits per target domain
}

// RateLimiter implements rate limiting guardrail
type RateLimiter struct {
	config RateLimiterConfig
	name   string

	// now supplies the current time. It defaults to time.Now in production;
	// tests inject a controllable clock via WithClock so token-bucket refill
	// is driven by virtual time instead of wall-clock + scheduler behavior.
	now func() time.Time

	// Global limiter (when PerTarget is false)
	global *rate.Limiter

	// Per-target limiters (when PerTarget is true)
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

// RateLimiterOption customizes a RateLimiter at construction time.
type RateLimiterOption func(*RateLimiter)

// WithClock injects a custom time source for the rate limiter's token bucket.
// It is a test seam for deterministic, virtual-time tests; production code never
// sets it, so the default time.Now behavior is unchanged. A nil clock is ignored.
func WithClock(now func() time.Time) RateLimiterOption {
	return func(r *RateLimiter) {
		if now != nil {
			r.now = now
		}
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimiterConfig, opts ...RateLimiterOption) *RateLimiter {
	// Default burst size to MaxRequests if not set
	if config.BurstSize == 0 {
		config.BurstSize = config.MaxRequests
	}

	// Calculate rate as requests per second
	ratePerSecond := float64(config.MaxRequests) / config.Window.Seconds()

	rl := &RateLimiter{
		config:   config,
		name:     "rate-limiter",
		now:      time.Now,
		limiters: make(map[string]*rate.Limiter),
	}

	for _, opt := range opts {
		opt(rl)
	}

	// Create global limiter if not per-target
	if !config.PerTarget {
		rl.global = rate.NewLimiter(rate.Limit(ratePerSecond), config.BurstSize)
	}

	return rl
}

// Name returns the name of the guardrail
func (r *RateLimiter) Name() string {
	return r.name
}

// Type returns the type of guardrail
func (r *RateLimiter) Type() guardrail.GuardrailType {
	return guardrail.GuardrailTypeRate
}

// CheckInput validates input against rate limits
func (r *RateLimiter) CheckInput(ctx context.Context, input guardrail.GuardrailInput) (guardrail.GuardrailResult, error) {
	var limiter *rate.Limiter

	if r.config.PerTarget {
		// Extract domain from URL
		domain := ""
		if input.TargetInfo != nil {
			domain = r.extractDomain(input.TargetInfo.URL)
		} else {
			domain = "default"
		}
		limiter = r.getOrCreateLimiter(domain)
	} else {
		// Use global limiter
		limiter = r.global
	}

	// Check if we can allow this request. AllowN/ReserveN take an explicit
	// timestamp so token-bucket refill is driven by r.now (time.Now in
	// production, a virtual clock under test) rather than an implicit wall clock.
	now := r.now()
	if !limiter.AllowN(now, 1) {
		// Calculate retry-after duration
		reservation := limiter.ReserveN(now, 1)
		delay := reservation.DelayFrom(now)
		reservation.Cancel() // Cancel the reservation since we're blocking

		result := guardrail.NewBlockResult(
			fmt.Sprintf("rate limit exceeded: max %d requests per %s", r.config.MaxRequests, r.config.Window),
		)
		result.Metadata = map[string]any{
			"retry_after_seconds": delay.Seconds(),
			"retry_after":         delay.String(),
		}

		return result, nil
	}

	return guardrail.NewAllowResult(), nil
}

// CheckOutput allows all output (rate limiting is about input requests)
func (r *RateLimiter) CheckOutput(ctx context.Context, output guardrail.GuardrailOutput) (guardrail.GuardrailResult, error) {
	// Rate limiting is typically only for input
	return guardrail.NewAllowResult(), nil
}

// getOrCreateLimiter gets or creates a limiter for a target domain
func (r *RateLimiter) getOrCreateLimiter(domain string) *rate.Limiter {
	// Fast path: read lock
	r.mu.RLock()
	limiter, exists := r.limiters[domain]
	r.mu.RUnlock()

	if exists {
		return limiter
	}

	// Slow path: write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check in case another goroutine created it
	limiter, exists = r.limiters[domain]
	if exists {
		return limiter
	}

	// Calculate rate as requests per second
	ratePerSecond := float64(r.config.MaxRequests) / r.config.Window.Seconds()

	// Create new limiter
	limiter = rate.NewLimiter(rate.Limit(ratePerSecond), r.config.BurstSize)
	r.limiters[domain] = limiter

	return limiter
}

// extractDomain extracts the domain from a URL
func (r *RateLimiter) extractDomain(urlStr string) string {
	if urlStr == "" {
		return "default"
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "default"
	}

	domain := parsedURL.Hostname()
	if domain == "" {
		return "default"
	}

	return domain
}
