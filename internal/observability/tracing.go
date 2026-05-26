package observability

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/pkg/version"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc/credentials"
)

const (
	defaultBatchTimeout = 5 * time.Second
	defaultServiceName  = "gibson"
)

// TracingOption is a functional option for configuring tracing initialization.
type TracingOption func(*tracingOptions)

// tracingOptions holds configuration options for tracing initialization.
type tracingOptions struct {
	sampler      sdktrace.Sampler
	resource     *resource.Resource
	batchTimeout time.Duration
}

// WithSampler sets a custom sampler for the tracer provider.
// The sampler determines which traces are recorded based on sampling decisions.
func WithSampler(sampler sdktrace.Sampler) TracingOption {
	return func(o *tracingOptions) {
		o.sampler = sampler
	}
}

// WithResource sets a custom resource for the tracer provider.
// The resource describes the entity producing telemetry (service name, version, etc.).
func WithResource(res *resource.Resource) TracingOption {
	return func(o *tracingOptions) {
		o.resource = res
	}
}

// WithBatchTimeout sets the maximum time between batch exports.
// Spans will be exported when this timeout is reached, even if the batch is not full.
func WithBatchTimeout(timeout time.Duration) TracingOption {
	return func(o *tracingOptions) {
		o.batchTimeout = timeout
	}
}

// InitTracing initializes distributed tracing with the specified configuration.
// It supports multiple tracing providers: "langfuse", "otlp", and "noop".
//
// Parameters:
//   - ctx: Context for initialization and potential cancellation
//   - cfg: Tracing configuration including provider type, endpoint, and sampling
//   - langfuse: Langfuse-specific configuration (optional, used when provider is "langfuse")
//
// Returns:
//   - *sdktrace.TracerProvider: The initialized tracer provider
//   - error: Any error encountered during initialization
//
// When cfg.Enabled is false, returns a no-op tracer provider that doesn't record spans.
// The no-op provider has zero overhead and is safe to use in production.
func InitTracing(ctx context.Context, cfg TracingConfig, langfuse *LangfuseConfig, opts ...TracingOption) (*sdktrace.TracerProvider, error) {
	// Return no-op provider if tracing is disabled
	if !cfg.Enabled {
		return sdktrace.NewTracerProvider(), nil
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, WrapObservabilityError(ErrExporterConnection, "invalid tracing configuration", err)
	}

	// Set up default options
	options := &tracingOptions{
		batchTimeout: defaultBatchTimeout,
	}

	// Apply functional options
	for _, opt := range opts {
		opt(options)
	}

	// Create sampler based on sample rate if not provided
	if options.sampler == nil {
		options.sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	// Create resource if not provided
	if options.resource == nil {
		serviceName := cfg.ServiceName
		if serviceName == "" {
			serviceName = defaultServiceName
		}

		// Use resource.New to avoid schema URL conflicts when merging
		// resource.Default() and custom attributes with different schema versions
		res, err := resource.New(
			ctx,
			resource.WithAttributes(
				semconv.ServiceName(serviceName),
				semconv.ServiceVersion(version.Version),
			),
			resource.WithFromEnv(),      // Include environment variables
			resource.WithTelemetrySDK(), // Include SDK info
		)
		if err != nil {
			return nil, WrapObservabilityError(ErrExporterConnection, "failed to create resource", err)
		}
		options.resource = res
	}

	// Create exporter based on provider type
	var exporter sdktrace.SpanExporter
	var err error

	provider := strings.ToLower(cfg.Provider)
	switch provider {
	case "langfuse":
		// Langfuse integration has been moved to MissionTracer.
		// Use NewMissionTracer() directly instead of the OpenTelemetry provider.
		if langfuse == nil || langfuse.Host == "" || langfuse.PublicKey == "" || langfuse.SecretKey == "" {
			return nil, WrapObservabilityError(ErrExporterConnection,
				"langfuse provider requires LangfuseConfig with host, public_key, and secret_key. Use NewMissionTracer() instead", nil)
		}
		return nil, WrapObservabilityError(ErrExporterConnection,
			"langfuse provider is not supported in InitTracing. Use NewMissionTracer() directly for Langfuse integration", nil)

	case "otlp":
		// Build OTLP options based on TLS configuration
		otlpOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
		}

		// Configure TLS
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			// Use TLS with client certificate
			creds, err := credentials.NewClientTLSFromFile(cfg.TLSCertFile, "")
			if err != nil {
				return nil, WrapObservabilityError(ErrExporterConnection,
					"failed to load TLS credentials", err)
			}
			otlpOpts = append(otlpOpts, otlptracegrpc.WithTLSCredentials(creds))
		} else if cfg.InsecureMode {
			// Use insecure connection (only if explicitly opted in)
			otlpOpts = append(otlpOpts, otlptracegrpc.WithInsecure())
		} else {
			// Default: Use system TLS (no client cert, but verify server)
			creds := credentials.NewTLS(nil)
			otlpOpts = append(otlpOpts, otlptracegrpc.WithTLSCredentials(creds))
		}

		exporter, err = otlptracegrpc.New(ctx, otlpOpts...)
		if err != nil {
			return nil, NewExporterConnectionError(cfg.Endpoint, err)
		}

	case "noop":
		// Return no-op provider for explicit noop configuration
		return sdktrace.NewTracerProvider(), nil

	default:
		return nil, NewObservabilityError(ErrExporterConnection, fmt.Sprintf("unsupported tracing provider: %s (jaeger is no longer supported, use otlp)", cfg.Provider))
	}

	// Create tracer provider with batch span processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(options.batchTimeout),
		),
		sdktrace.WithSampler(options.sampler),
		sdktrace.WithResource(options.resource),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	return tp, nil
}

// ShutdownTracing gracefully shuts down the tracer provider, flushing any pending spans.
// It should be called before application exit to ensure all telemetry is exported.
//
// Parameters:
//   - ctx: Context with optional timeout for shutdown operation
//   - provider: The tracer provider to shut down
//
// Returns:
//   - error: Any error encountered during shutdown
//
// The context timeout determines how long to wait for pending spans to be exported.
// A reasonable timeout is 5-10 seconds to allow in-flight exports to complete.
func ShutdownTracing(ctx context.Context, provider *sdktrace.TracerProvider) error {
	if provider == nil {
		return nil
	}

	if err := provider.Shutdown(ctx); err != nil {
		return WrapObservabilityError(ErrShutdownTimeout, "failed to shutdown tracer provider", err)
	}

	return nil
}
