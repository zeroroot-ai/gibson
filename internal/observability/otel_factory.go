package observability

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	pcotel "github.com/zero-day-ai/platform-clients/observability"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OTelObservabilityStack holds all initialized OTel components for the Gibson daemon.
// The stack provides complete observability with traces and metrics exported to
// OTLP-compatible backends (Jaeger, Tempo, Honeycomb, Datadog, etc.).
//
// Thread Safety: All components are thread-safe for concurrent use.
//
// Lifecycle:
//  1. Initialize with InitOTelObservability()
//  2. Use components throughout mission execution
//  3. Close with Close() on daemon shutdown to flush buffered data
//
// Example:
//
//	stack, err := InitOTelObservability(ctx, cfg)
//	if err != nil {
//	    return err
//	}
//	defer stack.Close(context.Background())
type OTelObservabilityStack struct {
	// TracerProvider creates tracers for distributed tracing.
	// Used by middleware and tracer components to create spans.
	TracerProvider *sdktrace.TracerProvider

	// MeterProvider creates meters for recording metrics.
	// Used by metrics recorder to track LLM usage, tool calls, etc.
	MeterProvider *metric.MeterProvider

	// MissionTracer provides mission-aware tracing with LLM semantic conventions.
	// Used by the orchestrator and harness for structured observability.
	MissionTracer *OTelMissionTracer

	// MetricsRecorder records operational metrics (counters, histograms).
	// Used throughout the system to track resource usage and performance.
	MetricsRecorder *OTelMetricsRecorder

	// ContentConfig holds the content logging configuration.
	// Used by middleware and tracers to control prompt/completion capture.
	ContentConfig *ContentLoggingConfig
}

// OTelConfig contains configuration for initializing the OTel observability stack.
// This is converted from config.OTelObservabilityConfig during daemon startup.
type OTelConfig struct {
	// Enabled controls whether OTel is active (required: true)
	Enabled bool

	// Endpoint is the OTLP receiver endpoint (required, e.g., "http://localhost:4317")
	Endpoint string

	// Protocol is the OTLP protocol: "grpc" or "http" (default: "grpc")
	Protocol string

	// Headers are additional headers to send with OTLP requests (optional)
	// Example: {"Authorization": "Bearer token"}
	Headers map[string]string

	// ServiceName identifies this service in traces (default: "gibson")
	ServiceName string

	// ServiceVersion identifies the version of this service (default: "unknown")
	ServiceVersion string

	// ContentLogging configures prompt/completion capture (optional)
	ContentLogging *ContentLoggingConfig

	// BatchSize is the maximum number of spans/metrics to batch (default: 512)
	BatchSize int

	// BatchTimeout is the maximum time to wait before sending a partial batch (default: 5s)
	BatchTimeout time.Duration

	// RetryEnabled determines whether failed exports should be retried (default: true)
	RetryEnabled bool

	// RetryInitial is the initial backoff duration for retry attempts (default: 1s)
	RetryInitial time.Duration

	// RetryMax is the maximum backoff duration between retries (default: 30s)
	RetryMax time.Duration

	// RetryMaxElapsed is the maximum total time to spend retrying (default: 5m)
	RetryMaxElapsed time.Duration

	// Neo4jBrowserURL is the URL for Neo4j Browser (used for deep links in traces)
	Neo4jBrowserURL string

	// MetricsEnabled controls the OTel metric exporter independently of
	// traces. Default: true. Set to false when the OTLP target is a
	// trace-only backend (Langfuse, etc.) — the daemon installs a no-op
	// MeterProvider and emits no /v1/metrics requests, leaving traces
	// fully functional.
	MetricsEnabled bool
}

// InitOTelObservability initializes the complete OpenTelemetry observability stack.
// This function creates and wires together all OTel components for distributed tracing
// and metrics collection.
//
// Initialization Steps:
//  1. Create resource with service metadata
//  2. Create OTLP trace exporter (gRPC or HTTP based on protocol)
//  3. Create TracerProvider with batch span processor
//  4. Create OTLP metric exporter
//  5. Create MeterProvider with periodic reader
//  6. Create OTelMissionTracer for mission-aware tracing
//  7. Create OTelMetricsRecorder for operational metrics
//  8. Set global OTel providers for library instrumentation
//
// The function applies defaults for all zero-valued configuration fields
// and validates the configuration before initialization.
//
// Error Handling:
// Returns an error if any component fails to initialize. Callers should
// gracefully degrade by continuing without OTel observability.
//
// Parameters:
//   - ctx: Context for initialization (used for exporter warmup)
//   - cfg: Configuration for the OTel stack
//
// Returns:
//   - *OTelObservabilityStack: Initialized stack with all components
//   - error: Non-nil if initialization fails
//
// Example:
//
//	cfg := OTelConfig{
//	    Enabled:      true,
//	    Endpoint:     "http://localhost:4317",
//	    Protocol:     "grpc",
//	    ServiceName:  "gibson",
//	}
//	stack, err := InitOTelObservability(ctx, cfg)
//	if err != nil {
//	    log.Warn("failed to init otel, continuing without tracing", "error", err)
//	    return nil
//	}
//	defer stack.Close(context.Background())
func InitOTelObservability(ctx context.Context, cfg OTelConfig) (*OTelObservabilityStack, error) {
	// Validate configuration
	if !cfg.Enabled {
		return nil, fmt.Errorf("otel observability is not enabled")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required when otel observability is enabled")
	}

	// Apply defaults
	cfg.applyDefaults()

	// Construct Langfuse Basic auth header from env vars if not already set.
	// The config may reference ${LANGFUSE_AUTH_HEADER} which may not be available.
	// Fall back to constructing it from LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY.
	if publicKey := os.Getenv("LANGFUSE_PUBLIC_KEY"); publicKey != "" {
		if secretKey := os.Getenv("LANGFUSE_SECRET_KEY"); secretKey != "" {
			authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(publicKey+":"+secretKey))
			if cfg.Headers == nil {
				cfg.Headers = make(map[string]string)
			}
			// Only set if the existing Authorization header is missing or contains an unresolved variable
			if existing, ok := cfg.Headers["Authorization"]; !ok || existing == "" || strings.Contains(existing, "${") {
				cfg.Headers["Authorization"] = authHeader
				slog.Info("constructed Langfuse auth header from environment variables")
			}
		}
	}

	slog.Info("initializing opentelemetry observability stack",
		"endpoint", cfg.Endpoint,
		"protocol", cfg.Protocol,
		"service_name", cfg.ServiceName,
		"content_logging_enabled", cfg.ContentLogging != nil && cfg.ContentLogging.Enabled)

	// Create resource with service metadata
	// Resource attributes are attached to all spans and metrics
	// Use NewWithAttributes with a single schema URL to avoid schema conflicts
	// when merging resources. resource.Default() uses a different schema version.
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
	)

	// Initialize trace exporter based on protocol
	var traceExporter sdktrace.SpanExporter
	var err error
	switch cfg.Protocol {
	case "grpc":
		traceExporter, err = createGRPCTraceExporter(ctx, cfg)
	case "http":
		traceExporter, err = createHTTPTraceExporter(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s (must be grpc or http)", cfg.Protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create TracerProvider with batch span processor
	// Batch processor aggregates spans to reduce network overhead
	batchProcessor := sdktrace.NewBatchSpanProcessor(
		traceExporter,
		sdktrace.WithMaxExportBatchSize(cfg.BatchSize),
		sdktrace.WithBatchTimeout(cfg.BatchTimeout),
	)

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(batchProcessor),
		// Always sample in Gibson for complete observability
		// Production systems may want to use probabilistic sampling
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	slog.Info("created otel tracer provider",
		"batch_size", cfg.BatchSize,
		"batch_timeout", cfg.BatchTimeout)

	// Initialize metric exporter based on protocol — but only if metrics
	// export is enabled. When disabled (e.g. against Langfuse, which is
	// trace-only), skip the exporter entirely so we don't spam /v1/metrics
	// 404s or 500s every export interval. The MeterProvider below falls
	// back to its no-op shape when metricExporter is nil.
	var metricExporter metric.Exporter
	if cfg.MetricsEnabled {
		switch cfg.Protocol {
		case "grpc":
			metricExporter, err = createGRPCMetricExporter(ctx, cfg)
		case "http":
			metricExporter, err = createHTTPMetricExporter(ctx, cfg)
		default:
			return nil, fmt.Errorf("unsupported protocol: %s (must be grpc or http)", cfg.Protocol)
		}
		if err != nil {
			// Warn but continue - metrics are less critical than traces
			slog.Warn("failed to create metric exporter, continuing without metrics",
				"error", err)
			metricExporter = nil
		}
	} else {
		slog.Info("otel metric exporter disabled by config (trace-only mode)")
	}

	// Create MeterProvider with periodic reader
	// Periodic reader pushes metrics at regular intervals
	var meterProvider *metric.MeterProvider
	if metricExporter != nil {
		periodicReader := metric.NewPeriodicReader(
			metricExporter,
			metric.WithInterval(10*time.Second), // Push metrics every 10 seconds
		)

		meterProvider = metric.NewMeterProvider(
			metric.WithResource(res),
			metric.WithReader(periodicReader),
		)

		slog.Info("created otel meter provider",
			"push_interval", "10s")
	} else {
		// Create no-op meter provider if metrics failed
		meterProvider = metric.NewMeterProvider(
			metric.WithResource(res),
		)
		slog.Warn("using no-op meter provider due to metric exporter failure")
	}

	// Set global OTel providers for library instrumentation.
	// Delegate to platform-clients/observability so the global registration
	// follows the same pattern used across all platform services (ext-authz,
	// tenant-operator, etc.). This also registers the composite propagator
	// (TraceContext + Baggage) consistently.
	//
	// Note: platform-clients/observability.Init uses an idempotent per-service
	// cache so calling it here (after we've already built our providers) has
	// no effect on the providers it constructs. We only need its side effect of
	// registering globals — but since it builds its own providers we set our
	// providers explicitly below after the Init call.
	_, _ = pcotel.Init("gibson",
		pcotel.WithOTLPEndpoint(cfg.Endpoint),
	)
	// Override with our fully-configured daemon providers so domain-specific
	// features (Langfuse auth, content-logging, HTTP protocol, etc.) are
	// preserved. The platform-clients Init above already set the propagator.
	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(meterProvider)

	// Ensure the W3C TraceContext + Baggage propagators are set. platform-clients
	// sets these too but we re-apply defensively in case Init was cached.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("set global otel providers and propagators (platform-clients/observability pattern)")

	// Create OTelMissionTracer with the providers
	missionTracer := NewOTelMissionTracer(tracerProvider, meterProvider, cfg.ContentLogging)
	if cfg.Neo4jBrowserURL != "" {
		missionTracer.WithNeo4jBrowserURL(cfg.Neo4jBrowserURL)
	}
	missionTracer.WithServiceName(cfg.ServiceName)

	slog.Info("created otel mission tracer",
		"neo4j_browser_url", cfg.Neo4jBrowserURL)

	// Create OTelMetricsRecorder with the meter provider
	metricsRecorder, err := NewOTelMetricsRecorder(meterProvider)
	if err != nil {
		// Warn but continue - metrics recording failures are not fatal
		slog.Warn("failed to create metrics recorder, continuing without metrics",
			"error", err)
		metricsRecorder = NoopMetricsRecorder()
	} else {
		slog.Info("created otel metrics recorder")
	}

	stack := &OTelObservabilityStack{
		TracerProvider:  tracerProvider,
		MeterProvider:   meterProvider,
		MissionTracer:   missionTracer,
		MetricsRecorder: metricsRecorder,
		ContentConfig:   cfg.ContentLogging,
	}

	slog.Info("opentelemetry observability stack initialized successfully")

	return stack, nil
}

// Close gracefully shuts down the OTel observability stack.
// This method flushes any buffered spans and metrics before returning.
// It should be called during daemon shutdown to ensure all telemetry is exported.
//
// The context controls the timeout for the shutdown operation. If the context
// is canceled before shutdown completes, buffered data may be lost.
//
// Thread Safety: Safe to call concurrently, but should only be called once.
//
// Parameters:
//   - ctx: Context with timeout for shutdown (recommended: 5-10s)
//
// Returns:
//   - error: First error encountered during shutdown (if any)
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//	if err := stack.Close(ctx); err != nil {
//	    log.Error("failed to close otel stack", "error", err)
//	}
func (s *OTelObservabilityStack) Close(ctx context.Context) error {
	slog.Info("shutting down opentelemetry observability stack")

	var firstErr error

	// Shutdown TracerProvider (flushes buffered spans)
	if s.TracerProvider != nil {
		if err := s.TracerProvider.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown tracer provider", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			slog.Info("tracer provider shutdown complete")
		}
	}

	// Shutdown MeterProvider (flushes buffered metrics)
	if s.MeterProvider != nil {
		if err := s.MeterProvider.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown meter provider", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			slog.Info("meter provider shutdown complete")
		}
	}

	if firstErr != nil {
		return fmt.Errorf("otel shutdown completed with errors: %w", firstErr)
	}

	slog.Info("opentelemetry observability stack shutdown complete")
	return nil
}

// applyDefaults fills in zero-valued fields with sensible defaults.
// This is called internally during InitOTelObservability.
func (c *OTelConfig) applyDefaults() {
	if c.ServiceName == "" {
		c.ServiceName = "gibson"
	}
	if c.ServiceVersion == "" {
		c.ServiceVersion = "unknown"
	}
	if c.Protocol == "" {
		c.Protocol = "grpc"
	}
	if c.BatchSize == 0 {
		c.BatchSize = 512
	}
	if c.BatchTimeout == 0 {
		c.BatchTimeout = 5 * time.Second
	}
	if c.RetryInitial == 0 {
		c.RetryInitial = 1 * time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = 30 * time.Second
	}
	if c.RetryMaxElapsed == 0 {
		c.RetryMaxElapsed = 5 * time.Minute
	}

	// Apply defaults to content logging config if provided
	if c.ContentLogging != nil {
		if c.ContentLogging.MaxPromptLength == 0 {
			c.ContentLogging.MaxPromptLength = 10000
		}
		if c.ContentLogging.MaxCompletionLength == 0 {
			c.ContentLogging.MaxCompletionLength = 10000
		}
		if len(c.ContentLogging.RedactPatterns) == 0 {
			c.ContentLogging.RedactPatterns = []string{
				`(?i)(api[_-]?key|password|secret|token|bearer)[=:\s]+\S+`,
			}
		}
	}
}

// createGRPCTraceExporter creates a gRPC-based OTLP trace exporter.
// This is the recommended protocol for production due to better performance and reliability.
func createGRPCTraceExporter(ctx context.Context, cfg OTelConfig) (sdktrace.SpanExporter, error) {
	// Build gRPC dial options
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithHeaders(cfg.Headers),
	}

	// Use insecure connection for http:// endpoints (dev/testing only)
	// Production should use https:// with TLS
	if len(cfg.Endpoint) >= 7 && cfg.Endpoint[:7] == "http://" {
		opts = append(opts, otlptracegrpc.WithInsecure())
		// Strip http:// prefix for gRPC dialer
		cfg.Endpoint = cfg.Endpoint[7:]
		opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
	}

	// Configure retry policy
	if cfg.RetryEnabled {
		opts = append(opts,
			otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
				Enabled:         true,
				InitialInterval: cfg.RetryInitial,
				MaxInterval:     cfg.RetryMax,
				MaxElapsedTime:  cfg.RetryMaxElapsed,
			}),
		)
	}

	// Configure gRPC connection options
	opts = append(opts, otlptracegrpc.WithDialOption(
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	))

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc trace exporter: %w", err)
	}

	return exporter, nil
}

// createHTTPTraceExporter creates an HTTP/protobuf-based OTLP trace exporter.
// This is useful for environments where gRPC is not available (e.g., some serverless platforms).
func createHTTPTraceExporter(ctx context.Context, cfg OTelConfig) (sdktrace.SpanExporter, error) {
	endpoint := cfg.Endpoint

	// Strip http:// or https:// prefix - WithEndpoint expects host:port only
	// The scheme is controlled by WithInsecure() option
	insecure := false
	if len(endpoint) >= 8 && endpoint[:8] == "https://" {
		endpoint = endpoint[8:]
	} else if len(endpoint) >= 7 && endpoint[:7] == "http://" {
		endpoint = endpoint[7:]
		insecure = true
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithHeaders(cfg.Headers),
		// Langfuse uses a custom OTEL path instead of the standard /v1/traces
		otlptracehttp.WithURLPath("/api/public/otel/v1/traces"),
	}

	// Use insecure connection for http:// endpoints (dev/testing only)
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	// Configure retry policy
	if cfg.RetryEnabled {
		opts = append(opts,
			otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
				Enabled:         true,
				InitialInterval: cfg.RetryInitial,
				MaxInterval:     cfg.RetryMax,
				MaxElapsedTime:  cfg.RetryMaxElapsed,
			}),
		)
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create http trace exporter: %w", err)
	}

	return exporter, nil
}

// createGRPCMetricExporter creates a gRPC-based OTLP metric exporter.
func createGRPCMetricExporter(ctx context.Context, cfg OTelConfig) (metric.Exporter, error) {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
		otlpmetricgrpc.WithHeaders(cfg.Headers),
	}

	// Use insecure connection for http:// endpoints
	if len(cfg.Endpoint) >= 7 && cfg.Endpoint[:7] == "http://" {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
		// Strip http:// prefix for gRPC dialer
		cfg.Endpoint = cfg.Endpoint[7:]
		opts = append(opts, otlpmetricgrpc.WithEndpoint(cfg.Endpoint))
	}

	// Configure retry policy
	if cfg.RetryEnabled {
		opts = append(opts,
			otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{
				Enabled:         true,
				InitialInterval: cfg.RetryInitial,
				MaxInterval:     cfg.RetryMax,
				MaxElapsedTime:  cfg.RetryMaxElapsed,
			}),
		)
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc metric exporter: %w", err)
	}

	return exporter, nil
}

// createHTTPMetricExporter creates an HTTP/protobuf-based OTLP metric exporter.
func createHTTPMetricExporter(ctx context.Context, cfg OTelConfig) (metric.Exporter, error) {
	endpoint := cfg.Endpoint

	// Strip http:// or https:// prefix - WithEndpoint expects host:port only
	// The scheme is controlled by WithInsecure() option
	insecure := false
	if len(endpoint) >= 8 && endpoint[:8] == "https://" {
		endpoint = endpoint[8:]
	} else if len(endpoint) >= 7 && endpoint[:7] == "http://" {
		endpoint = endpoint[7:]
		insecure = true
	}

	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithHeaders(cfg.Headers),
	}

	// Use insecure connection for http:// endpoints
	if insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	// Configure retry policy
	if cfg.RetryEnabled {
		opts = append(opts,
			otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{
				Enabled:         true,
				InitialInterval: cfg.RetryInitial,
				MaxInterval:     cfg.RetryMax,
				MaxElapsedTime:  cfg.RetryMaxElapsed,
			}),
		)
	}

	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create http metric exporter: %w", err)
	}

	return exporter, nil
}
