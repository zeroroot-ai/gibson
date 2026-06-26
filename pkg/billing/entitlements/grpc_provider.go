package entitlements

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	entitlementsv1 "github.com/zeroroot-ai/gibson/pkg/billing/entitlements/v1"
)

// GRPCProviderOptions configures a caching gRPC-client Provider.
type GRPCProviderOptions struct {
	// Endpoint is the "host:port" of the EntitlementsService server.
	// Required.
	Endpoint string

	// BillingServiceSVID is the SPIFFE ID the daemon expects to see in the
	// billing service's leaf certificate during the mTLS handshake. When
	// empty, the TLS config uses tlsconfig.AuthorizeAny() (permissive;
	// suitable for tests / loopback environments). In production this MUST
	// be set to the billing service's SPIFFE ID
	// (e.g. "spiffe://zeroroot.ai/platform/billing").
	BillingServiceSVID string

	// WorkloadAPISocket overrides the SPIRE agent socket path. When empty,
	// go-spiffe uses the SPIFFE_ENDPOINT_SOCKET env var (the chart's pod
	// spec mounts the CSI socket there). Tests pass a path here to avoid
	// blocking on a real SPIRE agent.
	WorkloadAPISocket string

	// CacheTTL is the cache lifetime for a fetched Limits entry. Zero uses
	// DefaultProviderTTL (60 s). Matches the configProvider's default so
	// callers see the same freshness semantics regardless of which backend
	// is selected.
	CacheTTL time.Duration

	// Logger is used for fail-open error reporting. Defaults to
	// slog.Default() when nil.
	Logger *slog.Logger

	// dialConn is a pre-dialed connection for tests. When non-nil, the
	// X509Source / SPIFFE dial path is skipped entirely.
	dialConn grpc.ClientConnInterface
}

// grpcProvider is a caching Provider that calls EntitlementsService/GetLimits
// over SPIFFE mTLS gRPC. It satisfies Invalidator so
// component.QuotaManager.InvalidateCache can drop a stale cached entry.
//
// Fail-open contract: any transport error or non-OK gRPC status causes
// Limits to return the zero value (unlimited) — matching the pre-seam
// UnlimitedProvider / configProvider fail-open behaviour.
type grpcProvider struct {
	client entitlementsv1.EntitlementsServiceClient
	// conn and source are owned by this provider and closed on Close.
	conn   *grpc.ClientConn
	source *workloadapi.X509Source

	cacheTTL time.Duration
	logger   *slog.Logger

	mu    sync.RWMutex
	cache map[string]limitsCacheEntry
}

// NewGRPCProvider dials the EntitlementsService at opts.Endpoint over SPIFFE
// mTLS and returns a Provider whose Limits calls are cached with a TTL. The
// returned value also satisfies Invalidator.
//
// The SPIFFE X509Source streams continuous SVID rotations; callers should
// construct exactly ONE grpcProvider per daemon process and reuse it.
//
// Returns (nil, nil) only when opts.dialConn is nil AND opts.Endpoint is
// empty — the caller interprets that as "use the OSS default". In all other
// cases either a live Provider or an error is returned.
func NewGRPCProvider(opts GRPCProviderOptions) (Provider, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("entitlements: NewGRPCProvider: Endpoint must not be empty")
	}

	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = DefaultProviderTTL
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	p := &grpcProvider{
		cacheTTL: ttl,
		logger:   logger,
		cache:    make(map[string]limitsCacheEntry),
	}

	// Tests may inject a pre-dialed connection to avoid the SPIRE path.
	if opts.dialConn != nil {
		p.client = entitlementsv1.NewEntitlementsServiceClient(opts.dialConn)
		return p, nil
	}

	// Production path: open a streaming X509Source from the SPIRE Workload API
	// and build an mTLS client config that authorizes the billing service's SVID.
	var sourceOpts []workloadapi.X509SourceOption
	if s := opts.WorkloadAPISocket; s != "" {
		sourceOpts = append(sourceOpts, workloadapi.WithClientOptions(workloadapi.WithAddr(s)))
	}
	source, err := workloadapi.NewX509Source(context.Background(), sourceOpts...)
	if err != nil {
		return nil, fmt.Errorf("entitlements: open SPIRE X509Source (socket=%q): %w",
			opts.WorkloadAPISocket, err)
	}

	var authorizer tlsconfig.Authorizer
	if opts.BillingServiceSVID != "" {
		id, err := spiffeid.FromString(opts.BillingServiceSVID)
		if err != nil {
			_ = source.Close()
			return nil, fmt.Errorf("entitlements: BillingServiceSVID %q is not a valid SPIFFE ID: %w",
				opts.BillingServiceSVID, err)
		}
		authorizer = tlsconfig.AuthorizeID(id)
	} else {
		authorizer = tlsconfig.AuthorizeAny()
	}

	tlsCfg := tlsconfig.MTLSClientConfig(source, source, authorizer)
	conn, err := grpc.NewClient(opts.Endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		_ = source.Close()
		return nil, fmt.Errorf("entitlements: dial billing service %q: %w",
			opts.Endpoint, err)
	}

	p.conn = conn
	p.source = source
	p.client = entitlementsv1.NewEntitlementsServiceClient(conn)
	return p, nil
}

// Limits implements Provider. It serves a cached value when fresh, else calls
// GetLimits. Any RPC error causes a fail-open return of the zero (unlimited)
// Limits value.
func (p *grpcProvider) Limits(ctx context.Context, tenantID string) (Limits, error) {
	if tenantID == "" {
		return Limits{}, errors.New("entitlements: tenant must not be empty")
	}

	p.mu.RLock()
	if e, ok := p.cache[tenantID]; ok && time.Now().Before(e.expireAt) {
		p.mu.RUnlock()
		return e.limits, nil
	}
	p.mu.RUnlock()

	resp, err := p.client.GetLimits(ctx, &entitlementsv1.GetLimitsRequest{
		TenantId: tenantID,
	})
	if err != nil {
		// Fail-open: log the error but return unlimited so enforcement never
		// blocks on a billing service blip.
		p.logger.Warn("entitlements: GetLimits RPC failed; using unlimited (fail-open)",
			"tenant", tenantID,
			"error", err,
		)
		return Limits{}, nil
	}

	lim := protoToLimits(resp)

	p.mu.Lock()
	p.cache[tenantID] = limitsCacheEntry{limits: lim, expireAt: time.Now().Add(p.cacheTTL)}
	p.mu.Unlock()

	return lim, nil
}

// Invalidate implements Invalidator. It drops the cached entry for tenantID
// so the next Limits call fetches a fresh value from the billing service.
// component.QuotaManager.InvalidateCache calls this when it detects that a
// tenant's quota config was just written.
func (p *grpcProvider) Invalidate(tenantID string) {
	p.mu.Lock()
	delete(p.cache, tenantID)
	p.mu.Unlock()
}

// Close releases the gRPC connection and the underlying X509Source. Safe to
// call on a provider constructed with a dialConn (no-op). Idempotent.
func (p *grpcProvider) Close() error {
	if p == nil {
		return nil
	}
	var connErr, srcErr error
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			connErr = fmt.Errorf("entitlements: close gRPC conn: %w", err)
		}
		p.conn = nil
	}
	if p.source != nil {
		if err := p.source.Close(); err != nil {
			srcErr = fmt.Errorf("entitlements: close X509Source: %w", err)
		}
		p.source = nil
	}
	if connErr != nil {
		return connErr
	}
	return srcErr
}

// protoToLimits converts an entitlementsv1.Limits proto message to the
// package-level Limits value. The proto uses int32 for concurrency fields and
// int64 for spend/token fields; the package type uses int and int64.
func protoToLimits(pb *entitlementsv1.Limits) Limits {
	if pb == nil {
		return Limits{}
	}
	return Limits{
		ConcurrentMissions:   int(pb.GetConcurrentMissions()),
		ConcurrentAgents:     int(pb.GetConcurrentAgents()),
		ConcurrentConnectors: int(pb.GetConcurrentConnectors()),
		MonthlyTokens:        pb.GetMonthlyTokens(),
		MonthlySpendUSDCents: pb.GetMonthlySpendUsdCents(),
	}
}
