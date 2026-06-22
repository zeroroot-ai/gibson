// Package fga: platform-clients adapter.
//
// This file wires the platform-clients authz.FGAClient into the existing
// fga.FGAClient interface so the cache + checker code in this package is
// unchanged while ext-authz picks up the per-call-timeout floor and
// typed error sentinels from platform-clients.
//
// Audit findings closed by this file:
//   - ext-authz had no per-call FGA timeout floor: a stalled OpenFGA would
//     consume Envoy's entire 5s ext_authz budget. authz.FGAClient applies
//     a configured PerCallTimeout (default 1500ms) under the budget so
//     the stall surfaces as a local timeout with a metric and span before
//     Envoy aborts the request.
//   - FGA latency was untyped: there were no histograms — only the
//     extauthz_allowed_total / extauthz_denied_total counters. This file
//     adds an OTel histogram that records every Check round-trip
//     (allow/deny/timeout/unavailable) and exposes it via the shared
//     platform-clients/observability MeterProvider.
package fga

import (
	"context"
	"errors"
	"sync"
	"time"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/zeroroot-ai/gibson/internal/infra/authz"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/zeroroot-ai/gibson/internal/extauthz/headers"
)

// nowFn is package-level so tests can stub. Defaults to time.Now.
var nowFn = time.Now

// classifyOutcome maps the platform-clients authz error sentinels +
// allow/deny result to a low-cardinality attribute value for the OTel
// histogram and counter.
func classifyOutcome(resp authz.CheckResponse, err error) string {
	switch {
	case errors.Is(err, authz.ErrFGATimeout):
		return "timeout"
	case errors.Is(err, authz.ErrFGAUnavailable):
		return "unavailable"
	case errors.Is(err, authz.ErrInvalidArgument):
		return "invalid"
	case err != nil:
		return "error"
	case resp.Allowed:
		return "allow"
	default:
		return "deny"
	}
}

// otelMeter / otelHistograms are lazily initialised on the first FGA
// Check so package init order does not require the platform-clients
// observability.Init call to have completed.
var (
	otelOnce       sync.Once
	fgaCheckMillis metric.Float64Histogram
	fgaCheckCount  metric.Int64Counter
	cacheHitOTel   metric.Int64Counter
	cacheMissOTel  metric.Int64Counter
)

func initOTel() {
	otelOnce.Do(func() {
		meter := otel.GetMeterProvider().Meter("github.com/zeroroot-ai/gibson/internal/extauthz/fga")
		fgaCheckMillis, _ = meter.Float64Histogram(
			"extauthz_fga_check_duration_ms",
			metric.WithDescription("Latency of FGA Check calls (ms)."),
			metric.WithUnit("ms"),
		)
		fgaCheckCount, _ = meter.Int64Counter(
			"extauthz_fga_check_total",
			metric.WithDescription("Total FGA Check calls by outcome (allow/deny/timeout/unavailable/invalid)."),
		)
		cacheHitOTel, _ = meter.Int64Counter(
			"extauthz_fga_cache_hits",
			metric.WithDescription("FGA decision cache hits (OTel mirror of Prometheus extauthz_fga_cache_hits_total)."),
		)
		cacheMissOTel, _ = meter.Int64Counter(
			"extauthz_fga_cache_misses",
			metric.WithDescription("FGA decision cache misses (OTel mirror of Prometheus extauthz_fga_cache_misses_total)."),
		)
	})
}

// recordCacheHitOTel mirrors the Prometheus cache hit counter onto the
// OTel meter so platform-clients/observability OTLP export carries the
// signal alongside Prometheus scrape.
func recordCacheHitOTel(ctx context.Context, allowed bool) {
	initOTel()
	if cacheHitOTel == nil {
		return
	}
	decision := "deny"
	if allowed {
		decision = "allow"
	}
	cacheHitOTel.Add(ctx, 1, metric.WithAttributes(attribute.String("decision", decision)))
}

func recordCacheMissOTel(ctx context.Context) {
	initOTel()
	if cacheMissOTel == nil {
		return
	}
	cacheMissOTel.Add(ctx, 1)
}

// PlatformFGAOptions configures a NewPlatformFGAClient adapter.
type PlatformFGAOptions = authz.FGAClientOptions

// NewPlatformFGAClient constructs an FGAClient backed by the
// platform-clients authz package. The returned value implements this
// package's FGAClient interface, so the existing cache + checker code
// consumes it without modification.
//
// The PerCallTimeout floor in opts.PerCallTimeout is enforced inside
// the underlying platform-clients.authz client; this adapter only adds
// the OTel histogram + counter on top of every Check.
func NewPlatformFGAClient(opts authz.FGAClientOptions) (FGAClient, error) {
	inner, err := authz.NewFGAClient(opts)
	if err != nil {
		return nil, err
	}
	return &platformFGAAdapter{inner: inner}, nil
}

// platformFGAAdapter satisfies fga.FGAClient by exposing a Check(ctx)
// builder that drives the platform-clients FGAClient on Execute().
type platformFGAAdapter struct {
	inner authz.FGAClient
}

// Check returns a request builder. The OpenFGA-SDK call shape is
// preserved so the existing Checker / CachedChecker code is unchanged.
func (a *platformFGAAdapter) Check(ctx context.Context) fgaclient.SdkClientCheckRequestInterface {
	initOTel()
	return &platformFGAReq{adapter: a, ctx: ctx}
}

// platformFGAReq is the SDK-shaped check builder.
type platformFGAReq struct {
	adapter *platformFGAAdapter
	ctx     context.Context
	body    fgaclient.ClientCheckRequest
}

func (r *platformFGAReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *platformFGAReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	// Per-call options (model override, store override) aren't used by
	// ext-authz; the platform-clients FGAClient is constructed with the
	// fixed store + model.
	return r
}

func (r *platformFGAReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	start := nowFn()
	resp, err := r.adapter.inner.Check(r.ctx, authz.CheckRequest{
		User:     r.body.User,
		Relation: r.body.Relation,
		Object:   r.body.Object,
	})
	dur := nowFn().Sub(start)

	if fgaCheckMillis != nil {
		fgaCheckMillis.Record(r.ctx, float64(dur.Milliseconds()))
	}
	if fgaCheckCount != nil {
		outcome := classifyOutcome(resp, err)
		fgaCheckCount.Add(r.ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	}

	if err != nil {
		return nil, err
	}
	allowed := resp.Allowed
	return &fgaclient.ClientCheckResponse{
		CheckResponse: openfga.CheckResponse{Allowed: &allowed},
	}, nil
}

func (r *platformFGAReq) GetAuthorizationModelIdOverride() *string  { return nil }
func (r *platformFGAReq) GetStoreIdOverride() *string               { return nil }
func (r *platformFGAReq) GetContext() context.Context               { return r.ctx }
func (r *platformFGAReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *platformFGAReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// _ = headers ensures the headers import stays meaningful for vet when
// future callers add label dimensions referencing identity fields.
var _ = headers.Identity{}
