// Package observability — daemon-owned :9090 metrics listener.
//
// This file implements the TLS-only Prometheus scrape endpoint required by
// Spec security-hardening R20 (and tracked under
// week-2-hardening-ha-daemon-internal task 18, "Option (a)" decision —
// daemon-owned listener, not SDK healthhttp termination).
//
// Lifecycle: NewMetricsServer constructs an *http.Server pre-configured
// with the chart-managed `gibson-daemon-metrics-tls` Secret material
// (mounted at /etc/gibson/tls/metrics/*). The caller drives Serve(ctx)
// from a goroutine; cancelling the parent context triggers a graceful
// http.Server.Shutdown.
//
// Failure mode: fail-fast. If any of CertPath / KeyPath / ClientCAPath is
// missing or unreadable at startup the constructor returns an error and the
// daemon refuses to start. There is no plaintext fallback and no
// INSECURE_DEV escape hatch — Spec 3 R20 forbids both.
package observability

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsServerConfig drives the daemon's `:9090` TLS-only metrics listener.
//
// All four file paths must point at readable files. Handler is the concrete
// HTTP handler exposed at /metrics; callers typically construct it from
// promhttp.HandlerFor(prometheus.DefaultGatherer, …) so both the OTel
// prometheus exporter and the daemon's promauto-registered gauges/histograms
// land on the same scrape surface.
type MetricsServerConfig struct {
	// Addr is the host:port the listener binds. Defaults to ":9090"
	// when empty so chart-managed deployments don't have to surface an
	// override in every overlay.
	Addr string

	// CertPath is the daemon's server certificate (PEM-encoded).
	// Required.
	CertPath string

	// KeyPath is the private key paired with CertPath. Required.
	KeyPath string

	// ClientCAPath is the CA bundle used to verify Prometheus scrape
	// clients. Required — mTLS is mandatory for this listener.
	ClientCAPath string

	// Handler is the metrics HTTP handler. Required. When nil the
	// constructor returns an error (we don't silently default to the
	// global registry because the daemon may want to scope to a
	// non-default Gatherer).
	Handler http.Handler
}

// MetricsServer wraps an http.Server with a Serve(ctx) lifecycle so the
// daemon can run it under the same goroutine pattern as healthSubsystem and
// grpcSubsystem.
type MetricsServer struct {
	srv *http.Server
}

// NewMetricsServer constructs a TLS-only Prometheus metrics server.
//
// The returned server is wired for mutual TLS (RequireAndVerifyClientCert,
// MinVersion = TLS 1.3) using the chart-mounted cert material. Callers
// drive the lifecycle via Serve(ctx); see (*MetricsServer).Serve.
//
// Errors:
//   - returns a non-nil error if any cert/key/CA path is missing,
//     unreadable, or fails to parse;
//   - returns a non-nil error if Handler is nil.
//
// The daemon must abort startup on any of these — Spec security-hardening R20
// is fail-closed.
func NewMetricsServer(cfg MetricsServerConfig) (*MetricsServer, error) {
	if cfg.Handler == nil {
		return nil, errors.New("metrics: handler is required")
	}
	if cfg.CertPath == "" || cfg.KeyPath == "" || cfg.ClientCAPath == "" {
		return nil, fmt.Errorf("metrics: TLS material paths are required (cert=%q key=%q ca=%q)",
			cfg.CertPath, cfg.KeyPath, cfg.ClientCAPath)
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("metrics: load server cert/key from %s/%s: %w", cfg.CertPath, cfg.KeyPath, err)
	}

	caBytes, err := os.ReadFile(cfg.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("metrics: load client CA from %s: %w", cfg.ClientCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("metrics: client CA bundle at %s is not valid PEM", cfg.ClientCAPath)
	}

	addr := cfg.Addr
	if addr == "" {
		addr = ":9090"
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: cfg.Handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &MetricsServer{srv: srv}, nil
}

// Addr returns the configured bind address. Useful for log lines and tests.
func (s *MetricsServer) Addr() string {
	if s == nil || s.srv == nil {
		return ""
	}
	return s.srv.Addr
}

// Serve binds the listener and serves Prometheus scrapes over TLS until
// either the parent context is cancelled (graceful shutdown) or the
// underlying http.Server returns a non-recoverable error.
//
// Returns nil when ctx cancellation triggers a clean shutdown (the
// http.ErrServerClosed sentinel is treated as success). Returns the
// underlying error otherwise — the caller (daemon Start) should log and,
// per Spec R20, treat any non-nil return as a fail-closed condition.
func (s *MetricsServer) Serve(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return errors.New("metrics: server not initialised")
	}

	// Run ListenAndServeTLS on its own goroutine and translate
	// ctx cancellation into a graceful Shutdown call.
	errCh := make(chan error, 1)
	go func() {
		// Empty cert/key arguments tell ListenAndServeTLS to use the
		// pre-loaded TLSConfig.Certificates we set in NewMetricsServer.
		errCh <- s.srv.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("metrics: serve: %w", err)
	case <-ctx.Done():
		// Best-effort graceful shutdown with a hard upper bound. The
		// daemon's overall shutdown timeout is governed by ShutdownConfig;
		// we keep this short because /metrics requests are by design
		// quick scrapes with no long-poll behaviour.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		// Drain the goroutine so we don't leak it.
		<-errCh
		return nil
	}
}

// DefaultPrometheusHandler returns the standard /metrics HTTP handler bound
// to the global Prometheus registry. Both the OTel-Prometheus exporter
// (initPrometheusProvider) and the daemon's promauto-registered metrics
// land on the global registry, so this single handler captures the whole
// surface. Tests may pass their own handler via MetricsServerConfig.Handler.
func DefaultPrometheusHandler() http.Handler {
	return promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		// Per Prom guidance — surface internal errors as 500s so
		// scrape failures show up in `up` rather than silently
		// returning empty payloads.
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
}
