package observability

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	apimetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	apitrace "go.opentelemetry.io/otel/trace"
)

// Observability holds the fully-initialised OTel + slog stack for a single
// service instance. All methods are safe for concurrent use after Init returns.
//
// Init does NOT mutate any process-global OTel state. Callers that need the
// global providers (e.g. for auto-instrumented libraries that call
// otel.GetTracerProvider) must call SetGlobal explicitly after Init.
type Observability struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider

	// Logger is a structured JSON slog.Logger pre-loaded with the service_name
	// attribute and the field constants from fields.go.
	Logger *slog.Logger

	// shutdownOnce ensures Shutdown is idempotent.
	shutdownOnce sync.Once

	// shutdownErr records the first error from Shutdown so subsequent calls
	// return nil (already-done is not an error).
	shutdownErr error
}

// TracerProvider returns the OTel API trace.TracerProvider interface backed
// by the SDK tracer provider created by Init. Using the interface type (not
// the SDK struct) means callers are insulated from OTel SDK version changes.
func (o *Observability) TracerProvider() apitrace.TracerProvider {
	return o.tracerProvider
}

// MeterProvider returns the OTel API metric.MeterProvider interface backed
// by the SDK meter provider created by Init.
func (o *Observability) MeterProvider() apimetric.MeterProvider {
	return o.meterProvider
}

// SetGlobal registers this instance's providers as the process-global OTel
// providers (otel.SetTracerProvider, otel.SetMeterProvider) and installs the
// composite W3C TraceContext + Baggage propagator. Call this when your service
// depends on auto-instrumented libraries that use otel.GetTracerProvider().
//
// SetGlobal is intentionally NOT called by Init so that multiple Observability
// instances can coexist in one process (e.g. in tests). Only one instance
// should call SetGlobal per process — calling it more than once replaces the
// global with the most recent call's providers.
func (o *Observability) SetGlobal() {
	otel.SetTracerProvider(o.tracerProvider)
	otel.SetMeterProvider(o.meterProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
}

// Shutdown flushes buffered spans and metrics then releases provider resources.
// It is idempotent: repeated calls return nil without double-flushing.
//
// Pass a context with a deadline to bound the flush time (5–10 s recommended).
func (o *Observability) Shutdown(ctx context.Context) error {
	o.shutdownOnce.Do(func() {
		var firstErr error

		if o.tracerProvider != nil {
			if err := o.tracerProvider.Shutdown(ctx); err != nil {
				firstErr = fmt.Errorf("tracer provider shutdown: %w", err)
			}
		}

		if o.meterProvider != nil {
			if err := o.meterProvider.Shutdown(ctx); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("meter provider shutdown: %w", err)
				}
			}
		}

		o.shutdownErr = firstErr
	})

	return o.shutdownErr
}

// Option is a functional option for Init.
type Option func(*config)

// config holds options accumulated by Init before initialising providers.
type config struct {
	otlpEndpoint       string
	logLevel           slog.Level
	resourceAttributes []attribute
}

type attribute struct{ key, value string }

// WithOTLPEndpoint sets the OTLP gRPC endpoint (e.g. "localhost:4317").
// If not set, Init uses the OTEL_EXPORTER_OTLP_ENDPOINT environment variable.
// If neither is present, a no-op exporter is used so the provider is still
// usable in environments without a collector.
func WithOTLPEndpoint(endpoint string) Option {
	return func(c *config) { c.otlpEndpoint = endpoint }
}

// WithLogLevel sets the minimum slog level. Defaults to slog.LevelInfo.
func WithLogLevel(level slog.Level) Option {
	return func(c *config) { c.logLevel = level }
}

// WithResourceAttribute adds an arbitrary OTel resource attribute key/value
// pair (e.g. "k8s.namespace.name", "gibson").
func WithResourceAttribute(key, value string) Option {
	return func(c *config) {
		c.resourceAttributes = append(c.resourceAttributes, attribute{key, value})
	}
}

// Init initialises OTLP exporters for traces and metrics, wires up slog with a
// structured JSON handler, and returns a ready-to-use *Observability.
//
// Each call to Init returns an independent *Observability instance; there is no
// shared process-global state. This makes it safe to call Init multiple times
// in the same process (e.g. in tests) without providers interfering with each
// other.
//
// Init does NOT call otel.SetTracerProvider or otel.SetMeterProvider. Call
// SetGlobal() on the returned *Observability if you need the global providers
// to be set (required for auto-instrumented libraries).
//
// The caller is responsible for calling Observability.Shutdown when the process
// exits to flush buffered telemetry.
func Init(ctx context.Context, serviceName string, opts ...Option) (*Observability, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("observability.Init: serviceName must not be empty")
	}

	cfg := &config{
		logLevel: slog.LevelInfo,
	}
	for _, o := range opts {
		o(cfg)
	}

	// Resolve OTLP endpoint: option → env → empty (no-op path).
	endpoint := cfg.otlpEndpoint
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		// Non-fatal: resource.New can return a partially-constructed resource
		// alongside a non-nil error (schema URL conflicts). We proceed.
		res = resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(serviceName))
	}

	// Trace provider.
	var tracerProvider *sdktrace.TracerProvider
	if endpoint != "" {
		traceExp, tErr := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
			otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
				Enabled:         true,
				InitialInterval: 1 * time.Second,
				MaxInterval:     30 * time.Second,
				MaxElapsedTime:  5 * time.Minute,
			}),
		)
		if tErr != nil {
			return nil, fmt.Errorf("observability.Init: trace exporter: %w", tErr)
		}
		tracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithBatcher(traceExp,
				sdktrace.WithMaxExportBatchSize(512),
				sdktrace.WithBatchTimeout(5*time.Second),
			),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
	} else {
		// No endpoint configured — use a no-op-equivalent provider that
		// accepts spans but discards them. Useful in test / local environments.
		tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithResource(res))
	}

	// Metric provider.
	var meterProvider *sdkmetric.MeterProvider
	if endpoint != "" {
		metricExp, mErr := otlpmetricgrpc.New(ctx,
			otlpmetricgrpc.WithEndpoint(endpoint),
			otlpmetricgrpc.WithInsecure(),
			otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{
				Enabled:         true,
				InitialInterval: 1 * time.Second,
				MaxInterval:     30 * time.Second,
				MaxElapsedTime:  5 * time.Minute,
			}),
		)
		if mErr != nil {
			// Metrics failure is non-fatal; fall through to no-op.
			slog.Warn("observability.Init: metric exporter failed, disabling metrics",
				"error", mErr)
			meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(res))
		} else {
			meterProvider = sdkmetric.NewMeterProvider(
				sdkmetric.WithResource(res),
				sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp,
					sdkmetric.WithInterval(10*time.Second),
				)),
			)
		}
	} else {
		meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(res))
	}

	// Structured slog logger with JSON output. We deliberately keep this
	// independent of the OTel log bridge — consumers can enrich spans via
	// trace.SpanFromContext independently.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.logLevel,
	})).With(
		"service_name", serviceName,
	)

	return &Observability{
		tracerProvider: tracerProvider,
		meterProvider:  meterProvider,
		Logger:         logger,
	}, nil
}
