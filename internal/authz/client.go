package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// tracerName is the OpenTelemetry instrumentation scope for authz spans.
	tracerName = "gibson.authz"

	// spanCheck is the OTel span name for a single Check call.
	spanCheck = "gibson.authz.fga_check"

	// spanBatchCheck is the OTel span name for a BatchCheck call.
	spanBatchCheck = "gibson.authz.fga_batch_check"

	// spanWrite is the OTel span name for a Write call.
	spanWrite = "gibson.authz.fga_write"

	// spanDelete is the OTel span name for a Delete call.
	spanDelete = "gibson.authz.fga_delete"

	// spanListObjects is the OTel span name for a ListObjects call.
	spanListObjects = "gibson.authz.fga_list_objects"

	// spanListUsers is the OTel span name for a ListUsers call.
	spanListUsers = "gibson.authz.fga_list_users"

	// defaultTimeoutMs is the default FGA call timeout in milliseconds.
	defaultTimeoutMs = 500
)

// FgaConfig contains the configuration needed to construct an fgaAuthorizer.
type FgaConfig struct {
	// Endpoint is the HTTP endpoint for the OpenFGA server, e.g. "http://gibson-fga:8080".
	// Must include the scheme (http:// or https://).
	Endpoint string

	// StoreID is the OpenFGA store identifier (ULID format).
	StoreID string

	// ModelID is the OpenFGA authorization model identifier (ULID format).
	ModelID string

	// TimeoutMs is the per-call timeout in milliseconds. Defaults to 500ms.
	TimeoutMs int

	// TLSEnabled controls whether TLS is enabled. The Endpoint must be an https:// URL.
	TLSEnabled bool

	// Logger for structured log output. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// fgaAuthorizer is the real implementation of the Authorizer interface.
//
// It wraps the OpenFGA Go SDK client and adds:
//   - Input validation before any network call
//   - Context-aware timeouts via context.WithTimeout
//   - OTel span emission per method
//   - Typed error mapping from SDK errors to authz sentinel errors
//
// fgaAuthorizer is safe for concurrent use.
type fgaAuthorizer struct {
	client    *fgaclient.OpenFgaClient
	storeID   string
	modelID   string
	timeoutMs int
	logger    *slog.Logger
	tracer    trace.Tracer
}

// NewFgaAuthorizer creates a new fgaAuthorizer and validates connectivity.
//
// The constructor validates config fields and establishes an HTTP client to the
// FGA endpoint. It does NOT call Check or Write during construction (no side
// effects). Connectivity is verified by the daemon's startup probe via
// initAuthorizer(), not here.
func NewFgaAuthorizer(_ context.Context, cfg FgaConfig) (Authorizer, error) {
	if cfg.Endpoint == "" {
		return nil, newInvalidArgumentError("FgaConfig.Endpoint must not be empty")
	}
	if cfg.StoreID == "" {
		return nil, newInvalidArgumentError("FgaConfig.StoreID must not be empty")
	}
	if cfg.ModelID == "" {
		return nil, newInvalidArgumentError("FgaConfig.ModelID must not be empty")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	timeoutMs := cfg.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}

	// Normalize the endpoint: ensure it starts with a scheme.
	endpoint := cfg.Endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		// Default to http for in-cluster traffic (no TLS by default)
		endpoint = "http://" + endpoint
	}

	clientCfg := &fgaclient.ClientConfiguration{
		ApiUrl:               endpoint,
		StoreId:              cfg.StoreID,
		AuthorizationModelId: cfg.ModelID,
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeoutMs) * time.Millisecond * 2, // Transport timeout is 2x the per-call timeout
		},
	}

	sdkClient, err := fgaclient.NewSdkClient(clientCfg)
	if err != nil {
		return nil, newUnavailableError(fmt.Sprintf("failed to construct FGA client for endpoint %s", endpoint), err)
	}

	return &fgaAuthorizer{
		client:    sdkClient,
		storeID:   cfg.StoreID,
		modelID:   cfg.ModelID,
		timeoutMs: timeoutMs,
		logger:    logger,
		tracer:    otel.Tracer(tracerName),
	}, nil
}

// StoreID returns the FGA store ID this authorizer is connected to.
func (f *fgaAuthorizer) StoreID() string {
	return f.storeID
}

// ModelID returns the FGA authorization model ID in use.
func (f *fgaAuthorizer) ModelID() string {
	return f.modelID
}

// Close releases underlying HTTP connections.
func (f *fgaAuthorizer) Close() error {
	// The OpenFGA HTTP client does not have an explicit close; transport cleanup
	// happens via the context. This is a no-op.
	return nil
}

// callContext returns a context with the configured per-call timeout applied.
func (f *fgaAuthorizer) callContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(f.timeoutMs)*time.Millisecond)
}

// startSpan starts an OTel span with the authz tracer and records it in ctx.
func (f *fgaAuthorizer) startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return f.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// mapSDKError converts OpenFGA SDK errors into typed authz errors.
//
// The FGA SDK returns errors as error strings. We check for common patterns:
//   - context deadline exceeded → ErrFgaTimeout
//   - connection refused / unavailable / EOF → ErrFgaUnavailable
//   - everything else → ErrFgaUnavailable (conservative fail-closed)
func mapSDKError(err error) error {
	if err == nil {
		return nil
	}

	msg := err.Error()
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "context deadline exceeded"),
		strings.Contains(lower, "timeout"),
		strings.Contains(lower, "deadline"):
		return newTimeoutError("call exceeded configured timeout", err)

	case strings.Contains(lower, "connection refused"),
		strings.Contains(lower, "no such host"),
		strings.Contains(lower, "connection reset"),
		strings.Contains(lower, "eof"),
		strings.Contains(lower, "unavailable"),
		strings.Contains(lower, "dial"):
		return newUnavailableError("FGA service unreachable", err)

	default:
		// Unknown SDK error — treat as unavailable (fail-closed)
		return newUnavailableError("FGA SDK error", err)
	}
}

// recordSpanError sets error status on the span and logs it.
func (f *fgaAuthorizer) recordSpanError(span trace.Span, err error, operation string) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	f.logger.Error("authz: FGA call failed",
		"operation", operation,
		"error", err,
	)
}
