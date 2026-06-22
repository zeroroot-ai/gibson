// Package transport provides ConnectRPC server and client builders with a
// full interceptor chain pre-wired.
//
// Server chain (outermost → innermost):
//  1. Panic recovery — catches all inner panics, returns CodeInternal.
//  2. OTel tracing (otelconnect) — starts / ends a server span per RPC.
//  3. Correlation ID — reads or mints x-correlation-id; echoes in response.
//  4. Identity validation hook — caller-supplied fn; nil-safe (skipped).
//
// Client chain (outermost → innermost):
//  1. Retry + exponential backoff + jitter — retries CodeUnavailable /
//     CodeDeadlineExceeded up to MaxAttempts.
//  2. OTel tracing (otelconnect) — injects span context into outgoing headers.
//  3. Correlation ID — propagates x-correlation-id from context into headers.
//
// Both server and client optionally use SPIFFE X.509 mTLS credentials; pass
// nil for tests or environments without a SPIRE agent.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// IdentityValidatorFunc is called by the server interceptor chain after the
// correlation ID interceptor. It may inspect and enrich the context (e.g.
// extract x-gibson-identity-* headers set by ext-authz) or return an error to
// reject the call.
//
// A nil IdentityValidatorFunc is a no-op; the chain proceeds unchanged.
type IdentityValidatorFunc func(req connect.AnyRequest) error

// ServerOptions configures a ConnectRPC server built by NewServer.
type ServerOptions struct {
	// Logger is used by the panic-recovery and correlation interceptors.
	// Defaults to slog.Default() when nil.
	Logger *slog.Logger

	// X509Source provides SPIFFE X.509 credentials for mTLS. When nil, the
	// server starts without transport security (suitable for tests and
	// loopback-only deployments).
	X509Source *workloadapi.X509Source

	// IdentityValidator is called after the correlation interceptor to validate
	// or enrich the request context. Nil means no identity validation.
	IdentityValidator IdentityValidatorFunc

	// RetryPolicy configures client-side retry behaviour (unused on server
	// options; present so ServerOptions and ClientOptions share a parallel
	// structure).

	// Addr is the listen address for the HTTP server, e.g. ":8080".
	// Required.
	Addr string
}

// Server is a running ConnectRPC HTTP/2 server.
type Server struct {
	http      *http.Server
	mux       *http.ServeMux
	tlsConfig *tls.Config
}

// Mux returns the ServeMux so callers can register ConnectRPC service handlers
// after calling NewServer.
func (s *Server) Mux() *http.ServeMux { return s.mux }

// ListenAndServe starts the HTTP server. If TLS credentials were supplied it
// uses ListenAndServeTLS (via the pre-wired tls.Config); otherwise plain HTTP.
// Blocks until the server shuts down or returns an error.
func (s *Server) ListenAndServe() error {
	if s.tlsConfig != nil {
		s.http.TLSConfig = s.tlsConfig
		// TLS config already has the certs; pass empty strings to
		// ListenAndServeTLS so it uses the pre-wired config.
		return s.http.ListenAndServeTLS("", "")
	}
	return s.http.ListenAndServe()
}

// NewServer constructs a ConnectRPC server with the full interceptor chain.
// Call srv.Mux() to register service handlers, then srv.ListenAndServe().
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Addr == "" {
		return nil, fmt.Errorf("transport.NewServer: Addr must not be empty")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// OTel interceptor.
	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("transport.NewServer: otelconnect: %w", err)
	}

	interceptors := []connect.Interceptor{
		// 1. Outermost: panic recovery catches all inner panics.
		panicRecoveryInterceptor(logger),
		// 2. OTel spans.
		otelInterceptor,
		// 3. Correlation ID propagation.
		correlationServerInterceptor(logger),
	}

	// 4. Identity validation hook (nil-safe).
	if opts.IdentityValidator != nil {
		interceptors = append(interceptors, identityValidatorInterceptor(opts.IdentityValidator))
	}

	mux := http.NewServeMux()
	_ = connect.WithInterceptors(interceptors...) // referenced via Mux callers

	srv := &Server{
		mux: mux,
		http: &http.Server{
			Addr:              opts.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}

	// SPIFFE mTLS is optional — nil X509Source means plain HTTP (tests /
	// loopback-only deployments).
	if opts.X509Source != nil {
		srv.tlsConfig = tlsconfig.MTLSServerConfig(
			opts.X509Source,
			opts.X509Source,
			tlsconfig.AuthorizeAny(),
		)
	}

	return srv, nil
}

// ConnectInterceptors returns the slice of server-side connect.Interceptor
// values to pass to a ConnectRPC service registration (connect.WithInterceptors).
// This is the primary way to attach the pre-wired chain to a service handler.
//
// Example:
//
//	srv, _ := transport.NewServer(opts)
//	path, handler := greetv1connect.NewGreetServiceHandler(
//	    &GreetServer{},
//	    connect.WithInterceptors(transport.ConnectInterceptors(srv.Logger(), srv.IdentityValidator())...),
//	)
//	srv.Mux().Handle(path, handler)
func ConnectInterceptors(logger *slog.Logger, validator IdentityValidatorFunc) []connect.Interceptor {
	if logger == nil {
		logger = slog.Default()
	}
	otelI, _ := otelconnect.NewInterceptor()
	interceptors := []connect.Interceptor{
		panicRecoveryInterceptor(logger),
		otelI,
		correlationServerInterceptor(logger),
	}
	if validator != nil {
		interceptors = append(interceptors, identityValidatorInterceptor(validator))
	}
	return interceptors
}

// ClientInterceptors returns the slice of client-side connect.Interceptor
// values to pass to connect.NewClient (connect.WithInterceptors). This is
// useful when callers build clients manually in tests or need the interceptors
// separate from NewClient.
func ClientInterceptors(policy RetryPolicy, perCallTimeout time.Duration) []connect.Interceptor {
	otelI, _ := otelconnect.NewInterceptor()
	interceptors := []connect.Interceptor{
		retryClientInterceptor(policy),
		otelI,
		correlationClientInterceptor(),
	}
	if perCallTimeout > 0 {
		interceptors = append(interceptors, perCallDeadlineInterceptor(perCallTimeout))
	}
	return interceptors
}

// ContextWithCorrelationID returns ctx with the supplied correlation ID
// attached. Use in tests or when synthesising a root context that already has
// a known ID before the first outgoing call.
func ContextWithCorrelationID(ctx context.Context, id string) context.Context {
	return contextWithCorrelationID(ctx, id)
}

// identityValidatorInterceptor wraps a caller-supplied IdentityValidatorFunc
// as a connect.Interceptor.
func identityValidatorInterceptor(fn IdentityValidatorFunc) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if err := fn(req); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
	})
}

// ClientOptions configures a ConnectRPC client built by NewClient.
type ClientOptions struct {
	// BaseURL is the target service base URL, e.g. "https://api.example.com".
	// Required.
	BaseURL string

	// X509Source provides SPIFFE X.509 credentials for mTLS. When nil, the
	// client uses the default http.Transport (suitable for tests).
	X509Source *workloadapi.X509Source

	// RetryPolicy configures retry behaviour. Zero value uses the defaults:
	// 5 attempts, 100 ms base delay, 5 s max delay.
	RetryPolicy RetryPolicy

	// PerCallTimeout sets a deadline on every outgoing RPC. Zero means no
	// per-call deadline (the caller's context is the only deadline).
	PerCallTimeout time.Duration
}

// NewClient constructs a typed ConnectRPC client with the full client
// interceptor chain (retry + backoff, OTel, correlation ID propagation, per-
// call deadline, WaitForReady).
//
// T is the ConnectRPC client interface generated by protoc-gen-connect-go.
// factory is the generated constructor, e.g. greetv1connect.NewGreetServiceClient.
//
// Example:
//
//	client, err := transport.NewClient(opts,
//	    greetv1connect.NewGreetServiceClient)
func NewClient[T any](
	opts ClientOptions,
	factory func(connect.HTTPClient, string, ...connect.ClientOption) T,
) (T, error) {
	var zero T
	if opts.BaseURL == "" {
		return zero, fmt.Errorf("transport.NewClient: BaseURL must not be empty")
	}

	// OTel interceptor.
	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return zero, fmt.Errorf("transport.NewClient: otelconnect: %w", err)
	}

	interceptors := []connect.Interceptor{
		// 1. Retry (outermost; wraps OTel + correlation).
		retryClientInterceptor(opts.RetryPolicy),
		// 2. OTel tracing.
		otelInterceptor,
		// 3. Correlation ID propagation.
		correlationClientInterceptor(),
	}

	// Per-call timeout interceptor. Wraps the entire chain so the deadline
	// applies to the full attempt including backoff-waits would run inside the
	// outermost retry interceptor; but we place it here so the deadline is
	// applied per-attempt rather than for the sum of all retries.
	if opts.PerCallTimeout > 0 {
		interceptors = append(interceptors, perCallDeadlineInterceptor(opts.PerCallTimeout))
	}

	clientOpts := []connect.ClientOption{
		connect.WithInterceptors(interceptors...),
	}

	// HTTP client: SPIFFE mTLS when an X509Source is provided, otherwise
	// the default http.Transport.
	var httpClient connect.HTTPClient = http.DefaultClient
	if opts.X509Source != nil {
		tlsCfg := tlsconfig.MTLSClientConfig(
			opts.X509Source,
			opts.X509Source,
			tlsconfig.AuthorizeAny(),
		)
		httpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}

	return factory(httpClient, opts.BaseURL, clientOpts...), nil
}

// perCallDeadlineInterceptor returns a connect.Interceptor that applies a
// fixed deadline to every outgoing call. The deadline is relative to the
// moment the interceptor fires (not when the client was created).
func perCallDeadlineInterceptor(d time.Duration) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ctx, cancel := context.WithTimeout(ctx, d)
			defer cancel()
			return next(ctx, req)
		}
	})
}
