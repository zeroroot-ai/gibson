package providers

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sony/gobreaker"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/platform-clients/resilience"
)

// llmCircuitConfig returns the circuit-breaker configuration tuned for LLM
// workloads. LLM calls have high latency variance, so we use more conservative
// thresholds than the platform default (5/60s/30s):
//   - 10 consecutive failures to open (vs. default 5)
//   - 60 s accumulation interval (same as default)
//   - 60 s open/cool-down timeout (vs. default 30 s)
func llmCircuitConfig() resilience.CircuitConfig {
	return resilience.CircuitConfig{
		ConsecutiveFailures: 10,
		Interval:            60 * time.Second,
		Timeout:             60 * time.Second,
	}
}

// Prometheus gauge for LLM circuit breaker state.
// Values: 0=closed, 1=half-open, 2=open.
var llmCircuitStateGauge = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "gibson_llm_circuit_state",
		Help: "Current state of an LLM provider circuit breaker (0=closed, 1=half-open, 2=open).",
	},
	[]string{"provider"},
)

// circuitLLMProvider wraps any LLMProvider with a sony/gobreaker circuit
// breaker. When the circuit is open, Complete calls return immediately without
// making an outbound request, preventing latency pile-up during provider
// outages. The breaker applies only to Complete; streaming and tool calls pass
// through to the inner provider unchanged because they carry their own
// back-pressure mechanics.
type circuitLLMProvider struct {
	inner llm.LLMProvider
	cb    *gobreaker.CircuitBreaker
	name  string
}

// newCircuitLLMProvider wraps inner with a circuit breaker named after
// providerName. The gauge metric is initialised to 0 (closed).
func newCircuitLLMProvider(inner llm.LLMProvider, providerName string) *circuitLLMProvider {
	// Seed the gauge at 0 so it is visible in Prometheus from the moment the
	// provider is constructed, not only after the first state change.
	llmCircuitStateGauge.WithLabelValues(providerName).Set(0)

	cb := resilience.NewBreaker(
		"llm/"+providerName,
		llmCircuitConfig(),
		func(name string, from, to gobreaker.State) {
			llmCircuitStateGauge.WithLabelValues(providerName).Set(gobreakerStateToFloat(to))
		},
	)

	return &circuitLLMProvider{
		inner: inner,
		cb:    cb,
		name:  providerName,
	}
}

// gobreakerStateToFloat converts a gobreaker.State to the gauge encoding used
// by gibson_llm_circuit_state: 0=closed, 1=half-open, 2=open.
func gobreakerStateToFloat(s gobreaker.State) float64 {
	switch s {
	case gobreaker.StateClosed:
		return 0
	case gobreaker.StateHalfOpen:
		return 1
	case gobreaker.StateOpen:
		return 2
	default:
		return -1
	}
}

// Name returns the provider name.
func (c *circuitLLMProvider) Name() string { return c.name }

// Models delegates directly to the inner provider; model enumeration does not
// hit the inference endpoint and need not be circuit-broken.
func (c *circuitLLMProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return c.inner.Models(ctx)
}

// Complete routes the completion call through the circuit breaker. When the
// circuit is open, gobreaker.ErrOpenState is wrapped and returned immediately
// without making an outbound request.
func (c *circuitLLMProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	result, err := c.cb.Execute(func() (interface{}, error) {
		return c.inner.Complete(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return result.(*llm.CompletionResponse), nil
}

// CompleteWithTools routes tool-bearing completion calls through the circuit
// breaker, applying the same open/half-open semantics as Complete.
func (c *circuitLLMProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	result, err := c.cb.Execute(func() (interface{}, error) {
		return c.inner.CompleteWithTools(ctx, req, tools)
	})
	if err != nil {
		return nil, err
	}
	return result.(*llm.CompletionResponse), nil
}

// Stream delegates directly to the inner provider. Streaming calls manage
// back-pressure through their own channel mechanics; circuit-breaking at the
// stream-open level would cause confusing UX where streaming silently stops.
func (c *circuitLLMProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return c.inner.Stream(ctx, req)
}

// Health delegates to the inner provider. If the circuit is open we still
// want an accurate health signal from the upstream check.
func (c *circuitLLMProvider) Health(ctx context.Context) types.HealthStatus {
	return c.inner.Health(ctx)
}
