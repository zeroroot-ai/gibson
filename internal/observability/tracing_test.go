package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func TestInitTracing_Disabled(t *testing.T) {
	cfg := TracingConfig{
		Enabled: false,
	}

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, nil)

	require.NoError(t, err)
	require.NotNil(t, provider)

	// Verify it's a no-op provider by checking it doesn't export spans
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ShutdownTracing(shutdownCtx, provider)
	}()
}

func TestInitTracing_NoopProvider(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     true,
		Provider:    "noop",
		ServiceName: "test-service",
		Endpoint:    "http://localhost:4318",
		SampleRate:  1.0,
	}

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, nil)

	require.NoError(t, err)
	require.NotNil(t, provider)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ShutdownTracing(shutdownCtx, provider)
	}()
}

func TestInitTracing_InvalidConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		cfg       TracingConfig
		langfuse  *LangfuseConfig
		expectErr bool
	}{
		{
			name: "invalid provider",
			cfg: TracingConfig{
				Enabled:     true,
				Provider:    "invalid",
				ServiceName: "test-service",
				Endpoint:    "http://localhost:4318",
				SampleRate:  1.0,
			},
			expectErr: true,
		},
		{
			name: "invalid sample rate - too low",
			cfg: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				ServiceName: "test-service",
				Endpoint:    "http://localhost:4318",
				SampleRate:  -0.1,
			},
			expectErr: true,
		},
		{
			name: "invalid sample rate - too high",
			cfg: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				ServiceName: "test-service",
				Endpoint:    "http://localhost:4318",
				SampleRate:  1.5,
			},
			expectErr: true,
		},
		{
			name: "missing endpoint",
			cfg: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				ServiceName: "test-service",
				SampleRate:  1.0,
			},
			expectErr: true,
		},
		{
			name: "missing service name",
			cfg: TracingConfig{
				Enabled:    true,
				Provider:   "otlp",
				Endpoint:   "http://localhost:4318",
				SampleRate: 1.0,
			},
			expectErr: true,
		},
		{
			name: "langfuse without config",
			cfg: TracingConfig{
				Enabled:     true,
				Provider:    "langfuse",
				ServiceName: "test-service",
				Endpoint:    "http://localhost:4318",
				SampleRate:  1.0,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			provider, err := InitTracing(ctx, tt.cfg, tt.langfuse)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				if provider != nil {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = ShutdownTracing(shutdownCtx, provider)
				}
			}
		})
	}
}

func TestInitTracing_SamplingConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
	}{
		{
			name:       "no sampling (0.0)",
			sampleRate: 0.0,
		},
		{
			name:       "half sampling (0.5)",
			sampleRate: 0.5,
		},
		{
			name:       "full sampling (1.0)",
			sampleRate: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TracingConfig{
				Enabled:     true,
				Provider:    "noop",
				ServiceName: "test-service",
				Endpoint:    "http://localhost:4318",
				SampleRate:  tt.sampleRate,
			}

			ctx := context.Background()
			provider, err := InitTracing(ctx, cfg, nil)

			require.NoError(t, err)
			require.NotNil(t, provider)

			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = ShutdownTracing(shutdownCtx, provider)
			}()

			// The provider should be configured with the specified sample rate
			// We can't directly test sampling behavior without generating spans,
			// but we can verify the provider was created successfully
		})
	}
}

func TestInitTracing_WithCustomSampler(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     true,
		Provider:    "noop",
		ServiceName: "test-service",
		Endpoint:    "http://localhost:4318",
		SampleRate:  1.0,
	}

	// Create a custom always-on sampler
	customSampler := sdktrace.AlwaysSample()

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, nil, WithSampler(customSampler))

	require.NoError(t, err)
	require.NotNil(t, provider)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ShutdownTracing(shutdownCtx, provider)
	}()
}

func TestInitTracing_WithCustomResource(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     true,
		Provider:    "noop",
		ServiceName: "test-service",
		Endpoint:    "http://localhost:4318",
		SampleRate:  1.0,
	}

	// Create a custom resource
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("custom-service"),
		semconv.ServiceVersion("1.0.0"),
	)

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, nil, WithResource(res))

	require.NoError(t, err)
	require.NotNil(t, provider)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ShutdownTracing(shutdownCtx, provider)
	}()
}

func TestInitTracing_WithBatchTimeout(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     true,
		Provider:    "noop",
		ServiceName: "test-service",
		Endpoint:    "http://localhost:4318",
		SampleRate:  1.0,
	}

	customTimeout := 10 * time.Second

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, nil, WithBatchTimeout(customTimeout))

	require.NoError(t, err)
	require.NotNil(t, provider)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ShutdownTracing(shutdownCtx, provider)
	}()
}

func TestInitTracing_WithLangfuse(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     true,
		Provider:    "langfuse",
		ServiceName: "test-service",
		Endpoint:    "http://localhost:4318",
		SampleRate:  1.0,
	}

	langfuseCfg := &LangfuseConfig{
		PublicKey: "pk-test-key",
		SecretKey: "sk-test-key",
		Host:      "http://localhost:3000",
	}

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, langfuseCfg)

	// Langfuse is no longer supported via InitTracing - must use NewMissionTracer
	require.Error(t, err)
	require.Nil(t, provider)
	require.Contains(t, err.Error(), "Use NewMissionTracer() directly")
}

func TestInitTracing_WithInMemoryExporter(t *testing.T) {
	// This test uses an in-memory exporter to verify span collection
	// Note: We create the provider manually to inject the in-memory exporter

	// Create in-memory exporter
	exporter := tracetest.NewInMemoryExporter()

	// Create custom tracer provider with in-memory exporter
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("test-service"),
		semconv.ServiceVersion("1.0.0"),
	)

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
	)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ShutdownTracing(shutdownCtx, provider)
	}()

	// Create a span to verify it's collected
	tracer := provider.Tracer("test-tracer")
	ctx := context.Background()
	_, span := tracer.Start(ctx, "test-span")
	span.End()

	// Force flush
	flushErr := provider.ForceFlush(context.Background())
	require.NoError(t, flushErr)

	// Verify span was collected
	spans := exporter.GetSpans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "test-span", spans[0].Name)
}

func TestShutdownTracing_Success(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     true,
		Provider:    "noop",
		ServiceName: "test-service",
		Endpoint:    "http://localhost:4318",
		SampleRate:  1.0,
	}

	ctx := context.Background()
	provider, err := InitTracing(ctx, cfg, nil)

	require.NoError(t, err)
	require.NotNil(t, provider)

	// Shutdown should succeed
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = ShutdownTracing(shutdownCtx, provider)
	assert.NoError(t, err)
}

func TestShutdownTracing_NilProvider(t *testing.T) {
	ctx := context.Background()
	err := ShutdownTracing(ctx, nil)
	assert.NoError(t, err)
}

func TestShutdownTracing_Timeout(t *testing.T) {
	// Create a provider with in-memory exporter that has pending spans
	exporter := tracetest.NewInMemoryExporter()
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("test-service"),
		semconv.ServiceVersion("1.0.0"),
	)

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
	)

	// Create some spans
	tracer := provider.Tracer("test-tracer")
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, span := tracer.Start(ctx, "test-span")
		span.End()
	}

	// Use an already-cancelled context to simulate timeout
	shutdownCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ShutdownTracing(shutdownCtx, provider)
	// Should error because context is already cancelled
	assert.Error(t, err)
}

func TestTracingOptions(t *testing.T) {
	t.Run("WithSampler", func(t *testing.T) {
		opts := &tracingOptions{}
		sampler := sdktrace.AlwaysSample()

		opt := WithSampler(sampler)
		opt(opts)

		assert.Equal(t, sampler, opts.sampler)
	})

	t.Run("WithResource", func(t *testing.T) {
		opts := &tracingOptions{}
		res := resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("test"),
		)

		opt := WithResource(res)
		opt(opts)

		assert.Equal(t, res, opts.resource)
	})

	t.Run("WithBatchTimeout", func(t *testing.T) {
		opts := &tracingOptions{}
		timeout := 15 * time.Second

		opt := WithBatchTimeout(timeout)
		opt(opts)

		assert.Equal(t, timeout, opts.batchTimeout)
	})
}
