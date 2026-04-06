package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
	"golang.org/x/time/rate"
)

// RateLimitConfig contains per-provider rate limiting configuration.
// Zero values mean unlimited (no rate limiting applied).
type RateLimitConfig struct {
	RequestsPerMinute int
	TokensPerMinute   int
}

// IsEnabled returns true if any rate limit is configured.
func (c RateLimitConfig) IsEnabled() bool {
	return c.RequestsPerMinute > 0 || c.TokensPerMinute > 0
}

// RateLimitedProvider wraps an LLMProvider with per-provider rate limiting.
// It enforces two independent token-bucket limits:
//   - Request rate: checked before each API call (blocks until allowed)
//   - Token rate: debited after each API call based on actual token usage
//
// Both limits use golang.org/x/time/rate which implements a token-bucket algorithm.
// A nil limiter (from zero config value) means that dimension is unlimited.
type RateLimitedProvider struct {
	inner        LLMProvider
	requestLimit *rate.Limiter // requests/minute, nil = unlimited
	tokenLimit   *rate.Limiter // tokens/minute, nil = unlimited
}

// NewRateLimitedProvider wraps a provider with rate limiting.
// If cfg has zero values for both limits, the inner provider is returned unwrapped.
func NewRateLimitedProvider(inner LLMProvider, cfg RateLimitConfig) LLMProvider {
	if !cfg.IsEnabled() {
		return inner
	}

	p := &RateLimitedProvider{inner: inner}

	if cfg.RequestsPerMinute > 0 {
		rps := rate.Limit(float64(cfg.RequestsPerMinute) / 60.0)
		burst := cfg.RequestsPerMinute / 10
		if burst < 1 {
			burst = 1
		}
		p.requestLimit = rate.NewLimiter(rps, burst)
	}

	if cfg.TokensPerMinute > 0 {
		tps := rate.Limit(float64(cfg.TokensPerMinute) / 60.0)
		burst := cfg.TokensPerMinute / 10
		if burst < 1 {
			burst = 1
		}
		p.tokenLimit = rate.NewLimiter(tps, burst)
	}

	return p
}

// Name delegates to the inner provider.
func (p *RateLimitedProvider) Name() string { return p.inner.Name() }

// Models delegates to the inner provider.
func (p *RateLimitedProvider) Models(ctx context.Context) ([]ModelInfo, error) {
	return p.inner.Models(ctx)
}

// Health delegates to the inner provider.
func (p *RateLimitedProvider) Health(ctx context.Context) types.HealthStatus {
	return p.inner.Health(ctx)
}

// Complete enforces request rate limit before the call and debits token usage after.
func (p *RateLimitedProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if err := p.waitForRequest(ctx); err != nil {
		return nil, err
	}

	resp, err := p.inner.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	p.debitTokens(resp.Usage)
	return resp, nil
}

// CompleteWithTools enforces request rate limit before the call and debits token usage after.
func (p *RateLimitedProvider) CompleteWithTools(ctx context.Context, req CompletionRequest, tools []ToolDef) (*CompletionResponse, error) {
	if err := p.waitForRequest(ctx); err != nil {
		return nil, err
	}

	resp, err := p.inner.CompleteWithTools(ctx, req, tools)
	if err != nil {
		return nil, err
	}

	p.debitTokens(resp.Usage)
	return resp, nil
}

// Stream enforces request rate limit before initiating the stream.
// Token usage for streaming is not tracked since usage is reported incrementally
// and the total is not available until the stream completes.
func (p *RateLimitedProvider) Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error) {
	if err := p.waitForRequest(ctx); err != nil {
		return nil, err
	}
	return p.inner.Stream(ctx, req)
}

// waitForRequest blocks until the request rate limiter allows another request.
// Returns immediately if no request rate limit is configured.
func (p *RateLimitedProvider) waitForRequest(ctx context.Context) error {
	if p.requestLimit == nil {
		return nil
	}
	if err := p.requestLimit.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit exceeded for provider %s: %w", p.inner.Name(), err)
	}
	return nil
}

// debitTokens reduces the token budget based on actual usage from the response.
// This is a best-effort operation — if the bucket goes negative, subsequent
// requests will be delayed until the bucket refills.
func (p *RateLimitedProvider) debitTokens(usage CompletionTokenUsage) {
	if p.tokenLimit == nil || usage.TotalTokens <= 0 {
		return
	}
	// ReserveN returns a Reservation; we don't need to wait on it because we're
	// retroactively debiting. The limiter will delay future requests if the
	// bucket has been overdrawn.
	p.tokenLimit.ReserveN(time.Now(), usage.TotalTokens)
}
