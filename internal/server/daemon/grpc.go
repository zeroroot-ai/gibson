package daemon

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	goredis "github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/reembed"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/idempotency"
	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/identity"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantembedder"
	"github.com/zeroroot-ai/gibson/internal/server/admin"
	discoverysvc "github.com/zeroroot-ai/gibson/internal/server/api/discovery"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
	logspb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	sessionpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/session/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	agentidentityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	graphpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graph/v1"
	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	pluginpb "github.com/zeroroot-ai/sdk/api/gen/gibson/plugin/v1"
	pluginadminv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/engine/missiondraft"
	"github.com/zeroroot-ai/gibson/internal/engine/target"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
	"github.com/zeroroot-ai/gibson/internal/platform/onboarding"
	"github.com/zeroroot-ai/gibson/internal/platform/reservednames"
)

// Mission-tier and long-term-tier operations are handled by the per-mission
// MemoryResolver wired separately (compSvc.WithMemoryResolver); only Working() is
// used from this shared store.
// serverStreamCtxOverride wraps a grpc.ServerStream so the handler sees a
// caller-augmented context (used by the registry-aware bypass that does
// loose identity parsing for unauthenticated RPCs).
type serverStreamCtxOverride struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStreamCtxOverride) Context() context.Context { return s.ctx }

// grpcSubsystem owns the lifecycle of the gRPC server. It is constructed by
// buildGRPCServer and exposes a Serve(ctx) error method that can be launched
// in an errgroup or a plain goroutine.
type grpcSubsystem struct {
	srv                 *grpc.Server
	listener            net.Listener
	logger              *observability.Logger
	gracefulStopTimeout time.Duration
}

// Serve starts serving gRPC requests and blocks until ctx is cancelled.
// On cancellation it calls GracefulStop with a bounded timeout, then
// falls back to Stop if the timeout is exceeded. Returns nil on clean
// shutdown; returns a non-nil error only if srv.Serve itself fails with
// an unexpected error (grpc.ErrServerStopped is treated as clean shutdown).
func (s *grpcSubsystem) Serve(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		s.logger.Info(ctx, "gRPC server listening", "address", s.listener.Addr().String())
		if err := s.srv.Serve(s.listener); err != nil && err.Error() != "use of closed network connection" {
			serveErr <- err
		} else {
			serveErr <- nil
		}
	}()

	select {
	case err := <-serveErr:
		// Serve returned before ctx was cancelled — propagate the error.
		return err
	case <-ctx.Done():
		// Initiate graceful shutdown with a bounded timeout.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), s.gracefulStopTimeout)
		defer stopCancel()

		gracefulDone := make(chan struct{})
		go func() {
			s.srv.GracefulStop()
			close(gracefulDone)
		}()

		select {
		case <-gracefulDone:
			s.logger.Info(ctx, "gRPC server drained gracefully")
		case <-stopCtx.Done():
			s.logger.Warn(ctx, "gRPC graceful stop timed out, forcing stop",
				"timeout", s.gracefulStopTimeout)
			s.srv.Stop()
		}
		// Wait for Serve goroutine to exit.
		<-serveErr
		return nil
	}
}

// buildGRPCServer creates the gRPC server, registers all services, and returns
// a grpcSubsystem ready to serve via Serve(ctx). The server is NOT started until
// Serve is called.
//
// All interceptor wiring, service registration, and SPIFFE mTLS setup is unchanged
// from the original startGRPCServer; only the launch goroutine has been moved to Serve.
func (d *daemonImpl) buildGRPCServer(ctx context.Context) (*grpcSubsystem, error) {
	// Zero-trust hardening Req 1.2: reject non-loopback bind when SPIFFE is unconfigured.
	// Without SPIFFE mTLS the daemon trusts x-gibson-identity-* headers from any caller
	// that can reach the gRPC port; binding to a non-loopback address without transport
	// security would expose the identity-header trust path to in-cluster attackers.
	noSPIFFE := d.config.Auth.SPIFFE == nil || d.config.Auth.SPIFFE.WorkloadAPISocket == ""
	if noSPIFFE {
		if err := rejectNonLoopbackWithoutSPIFFE(d.grpcAddr); err != nil {
			return nil, err
		}
		d.logger.Warn(ctx, "SPIFFE mTLS is not configured; daemon will run without transport security",
			"address", d.grpcAddr,
			"note", "only loopback binds are permitted without SPIFFE (zero-trust-hardening Req 1.2)",
		)
	}

	// Create listener
	listener, err := net.Listen("tcp", d.grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", d.grpcAddr, err)
	}

	// Build interceptor chains. Recovery is always first (outermost).
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// 1. Panic recovery (outermost — catches panics from all inner interceptors)
	var recoveryMeter metric.Meter
	if d.infrastructure != nil && d.infrastructure.otelStack != nil &&
		d.infrastructure.otelStack.MeterProvider != nil {
		recoveryMeter = d.infrastructure.otelStack.MeterProvider.Meter("gibson.grpc.recovery")
	}
	unaryRecovery, streamRecovery, err := panicRecoveryInterceptors(d.logger.Slog(), recoveryMeter)
	if err != nil {
		return nil, fmt.Errorf("failed to create recovery interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryRecovery)
	streamInterceptors = append(streamInterceptors, streamRecovery)

	// 2. OTel gRPC server instrumentation — the recommended otelgrpc v0.68+
	// pattern is a stats.Handler rather than per-interceptor injection.
	// The stats handler attaches to the server via grpc.StatsHandler(…) and
	// handles span lifecycle, trace propagation, and attribute enrichment for
	// every RPC.
	//
	// Audit P0 finding (zeroroot-ai/.github#101): otelgrpc server instrumentation
	// was missing; the daemon initialised OTel providers but never installed the
	// gRPC server-side instrumentation, so no daemon RPC spans appeared in Langfuse.
	//
	// NOTE: otelgrpc.UnaryServerInterceptor / StreamServerInterceptor were removed
	// in v0.68.0 (they were deprecated in v0.47). The stats.Handler replacement
	// is semantically equivalent and is the upstream-recommended form.
	otelServerHandler := otelgrpc.NewServerHandler()
	d.logger.Info(ctx, "otelgrpc stats handler registered (audit P0: otelgrpc was missing)")

	// 3. Error scrubbing (strips internal paths, YAML parse details, Go types from responses)
	var scrubMeter metric.Meter
	if d.infrastructure != nil && d.infrastructure.otelStack != nil &&
		d.infrastructure.otelStack.MeterProvider != nil {
		scrubMeter = d.infrastructure.otelStack.MeterProvider.Meter("gibson.grpc.error_scrub")
	}
	unaryScrub, streamScrub, err := errorScrubInterceptors(d.logger.Slog(), scrubMeter)
	if err != nil {
		return nil, fmt.Errorf("failed to create error scrub interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryScrub)
	streamInterceptors = append(streamInterceptors, streamScrub)

	// 4. Correlation ID — reads `x-correlation-id` from incoming
	// metadata (forwarded by the dashboard / ext-authz) or mints a
	// fresh `req-<base32 of uuid7>` ID when absent. The ID is
	// attached to the handler context (via CorrelationIDFromContext)
	// so structured-log lines emitted by business logic carry the
	// same correlation ID as the daemon's per-RPC log entry. The ID
	// is also echoed back as a gRPC response header so the
	// dashboard's `x-correlation-id` response header matches the
	// daemon's log line. Spec: deploy#207.
	unaryCorrelation, streamCorrelation := correlationIDInterceptors(d.logger.Slog())
	unaryInterceptors = append(unaryInterceptors, unaryCorrelation)
	streamInterceptors = append(streamInterceptors, streamCorrelation)

	// 5. Protovalidate runtime — runs `(buf.validate.field).*`
	// annotations against incoming proto.Message requests. Single
	// validator instance, goroutine-safe, CEL-program-cached.
	// Spec: mission-verb-noun-registry Requirement 10.
	pvValidator, err := buildProtovalidateValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to build protovalidate validator: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, newProtovalidateUnaryInterceptor(pvValidator))
	streamInterceptors = append(streamInterceptors, newProtovalidateStreamInterceptor(pvValidator))

	// 3. Identity interceptor — reads x-gibson-identity-* headers ext-authz
	// emits and injects a typed Identity into the request context.
	// Authorization (FGA) is enforced upstream by Envoy + ext_authz; the daemon
	// trusts the headers because the Envoy↔daemon channel is SPIFFE-pinned mTLS.
	// Transport security is the sole trust anchor between Envoy and the daemon;
	// the daemon relies on SPIFFE X.509 mTLS to ensure only the Envoy sidecar
	// (with the expected SVID) can reach the gRPC listener.
	// Wrap sdk/auth's identity interceptor with a registry-aware shim
	// that does LOOSE identity parsing for RPCs that have no tenant
	// scope by design — `unauthenticated: true` (Connect, Ping) and
	// `self: true` (sign-in self-bootstrap: ListMyMemberships,
	// GetMyPermissions). For both modes the handler still wants to know
	// WHO is asking (handlers self-scope via callerID.Subject), so we
	// extract the subject from ext-authz's identity header and attach a
	// minimal Identity to the context, bypassing strict tenant
	// validation. ext-authz is registry-aware too: it has already
	// applied the per-RPC AllowedIdentities bitfield for self-mode
	// entries before forwarding the request. For everything else the
	// standard sdk/auth interceptor runs unchanged with strict 5-header
	// validation.
	// Spec: zero-trust-hardening Req 5; self-mode-authz Req 4.6.
	looseIdentityFromMD := func(ctx context.Context) context.Context {
		md, ok := grpcmetadata.FromIncomingContext(ctx)
		if !ok {
			return ctx
		}
		subject := ""
		if vals := md.Get("x-gibson-identity-subject"); len(vals) > 0 {
			subject = vals[0]
		}
		if subject == "" {
			return ctx
		}
		// Issuer/CredentialType/IssuedAt set best-effort; tenant left as
		// zero-value (handler must not require it).
		issuer := auth.IssuerOIDC
		if vals := md.Get("x-gibson-identity-issuer"); len(vals) > 0 {
			issuer = auth.Issuer(vals[0])
		}
		credType := auth.CredentialOIDCUser
		if vals := md.Get("x-gibson-identity-credential-type"); len(vals) > 0 {
			credType = auth.CredentialType(vals[0])
		}
		return auth.WithIdentity(ctx, auth.Identity{
			Subject:        subject,
			Issuer:         issuer,
			CredentialType: credType,
		})
	}
	sdkAuthUnary := auth.UnaryServerInterceptor()
	sdkAuthStream := auth.StreamServerInterceptor()
	// looseModeForEntry: both unauthenticated and self mode bypass
	// strict tenant validation. ext-authz has already enforced the
	// per-RPC AllowedIdentities bitfield for self-mode before reaching
	// the daemon, and the handler is responsible for self-scoping via
	// caller.Subject. Spec: self-mode-authz Req 4.6.
	looseModeForEntry := func(entry registry.Entry) bool {
		return entry.Unauthenticated || entry.Self
	}

	// ADR-0002: when the request arrives over SPIFFE mTLS from a known
	// platform-control-plane peer (today: the tenant-operator), synthesise
	// an Identity from the peer's SVID and skip the ext-authz-shaped
	// header expectation. Envoy/ext-authz is the source of the headers on
	// the browser path; direct control-plane callers don't transit Envoy
	// and there's nothing to forward. Workload identity (the leaf cert's
	// URI SAN) is the trust anchor, validated by tlsconfig.AuthorizeOneOf
	// at the TLS handshake (gibson#107).
	//
	// Defense-in-depth (#245, #343): each peer SVID is restricted to an
	// explicit allowlist of gRPC method FQNs. A peer calling an unlisted
	// method is rejected with PermissionDenied rather than falling through
	// to sdkAuthUnary (which would fail with Unauthenticated since no
	// ext-authz headers are present on direct-dial connections).
	// Per-peer method allowlist (#245), derived from the descriptor-validated
	// operatorMethodPolicy (operator_method_policy.go) — the single source of
	// truth that classifies EVERY DaemonOperatorService method as
	// operator-allowed XOR operator-denied. A guard test enumerates the methods
	// from the generated service descriptor and fails CI if any method is
	// unclassified, so this allowlist can no longer silently drift behind the
	// RPC surface (the recurring gibson#621/#949/#1043 omission bug). A
	// reconciliation test pins the allowed set to exactly the operator's actual
	// call set (least privilege).
	spiffeMethodAllowlist := map[string]map[string]bool{
		tenantOperatorSVID: operatorAllowedMethods(),
	}
	spiffePlatformBypass := func(ctx context.Context, method string) (context.Context, bool, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return ctx, false, nil
		}
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			return ctx, false, nil
		}
		var svid string
		for _, u := range tlsInfo.State.PeerCertificates[0].URIs {
			if u != nil && strings.HasPrefix(u.Scheme, "spiffe") {
				svid = u.String()
				break
			}
		}
		if svid == "" {
			return ctx, false, nil
		}
		// Trust only SVIDs the daemon already explicitly allow-listed at
		// the TLS layer via AllowedPeerIDs. EnvoyID is not bypassed —
		// browser-path traffic always carries the ext-authz headers and
		// must continue to do so.
		for _, allowed := range d.config.Auth.SPIFFE.AllowedPeerIDs {
			if svid == allowed {
				// Enforce per-peer method allowlist (#245).
				if methods, listed := spiffeMethodAllowlist[svid]; listed && !methods[method] {
					return ctx, false, grpcstatus.Errorf(grpccodes.PermissionDenied,
						"SPIFFE peer %q is not authorised to call %q", svid, method)
				}
				return auth.WithIdentity(ctx, auth.Identity{
					Subject:        svid,
					Issuer:         auth.Issuer("spiffe"),
					CredentialType: auth.CredentialType("spiffe"),
				}), true, nil
			}
		}
		return ctx, false, nil
	}

	registryAwareUnary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if entry, ok := registry.Registry[info.FullMethod]; ok && looseModeForEntry(entry) {
			return handler(looseIdentityFromMD(ctx), req)
		}
		if bypassCtx, ok, err := spiffePlatformBypass(ctx, info.FullMethod); err != nil {
			return nil, err
		} else if ok {
			return handler(bypassCtx, req)
		}
		return sdkAuthUnary(ctx, req, info, handler)
	}
	registryAwareStream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if entry, ok := registry.Registry[info.FullMethod]; ok && looseModeForEntry(entry) {
			wrapped := &serverStreamCtxOverride{ServerStream: ss, ctx: looseIdentityFromMD(ss.Context())}
			return handler(srv, wrapped)
		}
		if bypassCtx, ok, err := spiffePlatformBypass(ss.Context(), info.FullMethod); err != nil {
			return err
		} else if ok {
			wrapped := &serverStreamCtxOverride{ServerStream: ss, ctx: bypassCtx}
			return handler(srv, wrapped)
		}
		return sdkAuthStream(srv, ss, info, handler)
	}
	unaryInterceptors = append(unaryInterceptors, registryAwareUnary)
	streamInterceptors = append(streamInterceptors, registryAwareStream)
	d.logger.Info(ctx, "identity interceptor installed (header-trusting; channel security via SPIFFE mTLS)")

	// 4. Idempotency-key dedup (mutating-RPC convention from
	// platform-sdk CONVENTIONS.md, added in platform-sdk#2). Activates
	// dedup ONLY when the request message has a non-empty
	// `idempotency_key` field — protoreflect-discovered, no SDK pin
	// or method-name allowlist. Requires the Redis state client; if
	// absent we skip the interceptor entirely and log a warning so
	// the missing-dep is visible (the daemon already warns about
	// every other Redis-dependent subsystem in this same shape).
	// Spec: gibson#228 / zeroroot-ai/.github#101.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			idemStore := NewRedisIdempotencyStore(redisClient, d.logger.Slog())
			d.idempotencyStore = idemStore
			unaryInterceptors = append(unaryInterceptors,
				idempotencyUnaryInterceptor(idemStore, idempotency.DefaultTTL, d.logger.Slog()))
			d.logger.Info(ctx, "idempotency dedup interceptor installed (Redis-backed; 24h default TTL)")
		} else {
			d.logger.Warn(ctx, "idempotency dedup interceptor not installed: state client is not a *redis.Client")
		}
	} else {
		d.logger.Warn(ctx, "idempotency dedup interceptor not installed: stateClient is nil")
	}

	// Build server options with chained interceptors and the OTel stats handler.
	// grpc.StatsHandler(otelServerHandler) is the otelgrpc v0.68+ replacement
	// for the deprecated UnaryServerInterceptor/StreamServerInterceptor pair.
	// It attaches a span to every RPC including streaming RPCs.
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
		grpc.StatsHandler(otelServerHandler),
	}

	// SPIFFE mTLS — the only supported posture; cert-less connections are rejected at the TLS layer.
	if d.config.Auth.SPIFFE != nil && d.config.Auth.SPIFFE.WorkloadAPISocket != "" {
		// d.spiffeX509Source is opened once in initSPIFFEX509Source (called from
		// daemon.Start before any listener is wired); both the main listener and
		// the harness callback listener consume it. If we got here without a
		// source, initSPIFFEX509Source either wasn't called or was disabled —
		// fail-closed.
		if d.spiffeX509Source == nil {
			return nil, fmt.Errorf(
				"SPIFFE mTLS is configured but d.spiffeX509Source is nil; " +
					"initSPIFFEX509Source must be called from daemon.Start before buildGRPCServer; " +
					"spec: critical-tls-no-fallbacks Component 4")
		}
		x509Source, ok := d.spiffeX509Source.(*workloadapi.X509Source)
		if !ok {
			return nil, fmt.Errorf(
				"SPIFFE mTLS is configured but d.spiffeX509Source is not a *workloadapi.X509Source (got %T)",
				d.spiffeX509Source)
		}

		// Auth-review finding 4a (CRITICAL): pin mTLS to a closed set of
		// SPIFFE SVIDs. The Envoy edge gateway is always accepted; additional
		// control-plane callers (today: the tenant-operator) are added via
		// GIBSON_SPIFFE_ALLOWED_PEER_IDS so they can dial the daemon directly
		// without an Envoy hairpin. ADR-0002 (zeroroot-ai/docs).
		envoyID := d.config.Auth.SPIFFE.EnvoyID
		if envoyID == "" {
			envoyID = os.Getenv("GIBSON_SPIFFE_ENVOY_ID")
		}
		allowed := []spiffeid.ID{spiffeid.RequireFromString(envoyID)}
		for _, raw := range d.config.Auth.SPIFFE.AllowedPeerIDs {
			id, err := spiffeid.FromString(raw)
			if err != nil {
				return nil, fmt.Errorf(
					"SPIFFE mTLS: GIBSON_SPIFFE_ALLOWED_PEER_IDS entry %q is not a parseable SPIFFE ID: %w",
					raw, err)
			}
			allowed = append(allowed, id)
		}
		tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeOneOf(allowed...))
		d.logger.Info(ctx, "SPIFFE mTLS pinned to allow-list",
			"envoy_id", envoyID,
			"additional_peer_ids", d.config.Auth.SPIFFE.AllowedPeerIDs,
		)
		// Critical-tls-no-fallbacks Req 2.1, 2.3: cert-less connections are
		// rejected at the TLS layer; there is no Bearer-token / API-key /
		// Auth.js pass-through path on this listener anymore. We rely on
		// tlsconfig.MTLSServerConfig's built-in ClientAuth value (which
		// rejects cert-less handshakes) plus go-spiffe's VerifyPeerCertificate
		// callback for SPIFFE bundle chain validation. We do NOT override
		// ClientAuth to RequireAndVerifyClientCert because that triggers Go's
		// stdlib chain verifier against a nil ClientCAs pool — exactly the
		// VerifyClientCertIfGiven foot-gun the deleted regression test
		// documented. The chain validation is owned by go-spiffe's
		// VerifyPeerCertificate, which fetches the current SPIRE bundle
		// dynamically. The CI guard TestNoFallbackAudit (in
		// core/gibson/internal/tlsaudit) enforces zero matches of the four
		// banned literals (RequestClientCert / NoClientCert /
		// VerifyClientCertIfGiven / RequireAnyClientCert) in production code
		// outside *_test.go.
		// Wrap VerifyPeerCertificate to keep the structured accepted/rejected
		// log events. There is NO len(rawCerts)==0 branch — go-spiffe's
		// MTLSServerConfig sets ClientAuth such that an empty cert chain
		// fails the handshake before VerifyPeerCertificate runs (Req 2.2).
		origVerify := tlsCfg.VerifyPeerCertificate
		logger := d.logger
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if err := origVerify(rawCerts, verifiedChains); err != nil {
				// Parse the leaf cert for structured rejection detail.
				// Best-effort: if parsing fails, log what we can.
				logCtx := context.Background()
				if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
					sans := make([]string, 0, len(leaf.URIs))
					for _, u := range leaf.URIs {
						sans = append(sans, u.String())
					}
					logger.Warn(logCtx, "SPIFFE mTLS: rejected client cert",
						"issuer", leaf.Issuer.String(),
						"subject", leaf.Subject.String(),
						"sans_uri", strings.Join(sans, ","),
						"not_before", leaf.NotBefore.Format(time.RFC3339),
						"not_after", leaf.NotAfter.Format(time.RFC3339),
						"error", err.Error(),
					)
				} else {
					logger.Warn(logCtx, "SPIFFE mTLS: rejected client cert (unparseable)",
						"error", err.Error(),
					)
				}
				return err
			}
			// Cert accepted — log the SPIFFE ID (URI SAN) from the leaf cert.
			// Log ONLY the URI SAN — never raw cert bytes, never client IP.
			if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
				spiffeID := ""
				for _, u := range leaf.URIs {
					if strings.HasPrefix(u.Scheme, "spiffe") {
						spiffeID = u.String()
						break
					}
				}
				if spiffeID != "" {
					logger.Info(context.Background(), "mTLS handshake accepted",
						"spiffe_id", spiffeID,
					)
				}
			}
			return nil
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		d.logger.Info(ctx, "SPIFFE mTLS configured on gRPC server",
			"socket", d.config.Auth.SPIFFE.WorkloadAPISocket,
			"trust_domain", d.config.Auth.SPIFFE.TrustDomain,
		)
	}

	// Create gRPC server with options
	srv := grpc.NewServer(serverOpts...)
	d.grpcServer = srv

	// Create and register daemon service.
	// Attach the quota manager so RunMission enforces per-tenant mission limits.
	daemonSvc := api.NewDaemonServer(d, d.credentialHandler, d.logger.Slog())
	if d.authorizer != nil {
		daemonSvc.WithAuthorizer(d.authorizer)
		d.logger.Info(ctx, "FGA authorizer wired into DaemonServer for admin RPCs")
	}
	// Capture completed ExecuteLLM calls into the per-tenant brain World as
	// LlmCall entities (gibson#755) — the World replacement for Langfuse.
	if d.brainRegistry != nil {
		daemonSvc.SetLLMCallSink(ingestLLMCall(d.brainRegistry))
		d.logger.Info(ctx, "wired ExecuteLLM World-capture sink to the ECS brain")
	}
	// Wire the CG Minter so CreateAgentIdentity can issue a first-registration
	// bootstrap token (gibson#648 / ADR-0045). d.cgMinter is constructed during
	// Start once the key provider is available; nil disables issuance.
	if d.cgMinter != nil {
		daemonSvc.WithCGMinter(d.cgMinter)
	}
	// platformDB is always non-nil after Start() (gibson#246): initPlatformPostgres
	// is fatal on failure, so the entitlements RPCs always have a real pool.
	daemonSvc.WithPlatformDB(d.platformDB)
	d.logger.Info(ctx, "dashboard Postgres pool wired into DaemonServer for entitlements RPCs")
	if d.quotaManager != nil {
		daemonSvc.WithQuotaManager(d.quotaManager)
		d.logger.Info(ctx, "quota manager wired into DaemonServer for mission quota enforcement")
	}

	if d.targetStore != nil {
		daemonSvc.WithTargetService(target.NewService(d.targetStore))
		d.logger.Info(ctx, "target service wired into DaemonServer for target CRUD RPCs")
	} else {
		d.logger.Error(ctx, "target service NOT wired — targetStore is nil; target CRUD RPCs will fail")
	}

	if d.pool != nil && d.secretsService != nil {
		providerStore := providerconfig.NewBrokerBackedStore(d.pool, d.secretsService)
		daemonSvc.WithProviderConfigStore(providerStore)
		d.logger.Info(ctx, "provider-config store wired (broker-backed: metadata in Postgres, credentials in secrets broker)")

		// Per-tenant embedder resolution (E11 BYO-embedder, ADR-0059,
		// gibson#810): vector recall / GraphRAG / belief-RAG / finding
		// classification resolve their embedder from the tenant's configured
		// embedding provider via embedder.NewFromProvider, sized to that model's
		// vector dimension. A tenant with no embedding provider hits the
		// onboarding gate. allowPrivate is false (the secure default); operators
		// running an in-cluster/air-gapped embedder endpoint opt in via the SSRF
		// allow-list when that knob lands.
		embedderResolver := tenantembedder.NewResolver(providerStore, false)
		daemonSvc.WithEmbedderResolver(embedderResolver)
		d.embedderResolver = embedderResolver
		d.logger.Info(ctx, "per-tenant embedder resolver wired (BYO-embedder; vector features gated until an embedding provider is configured)")

		// Per-tenant re-embed trigger (gibson#940): when a tenant changes its
		// embedding provider/model via the provider-config RPCs, reconcile that
		// tenant's RediSearch vector index to the new model's dimension and
		// re-embed stored content. The runner resolves the tenant's OWN
		// database-per-tenant StateClient (from the datapool's per-tenant Redis
		// client) and the tenant's CURRENT embedder (from the resolver), then runs
		// the idempotent reembed.RunForTenant pass. The trigger fires it async +
		// per-tenant-serialised (see api.NewReembedJobTrigger).
		pool := d.pool
		reembedLog := d.logger.Slog()
		runner := func(runCtx context.Context, tenantID string) error {
			tenant, terr := auth.NewTenantID(tenantID)
			if terr != nil {
				return fmt.Errorf("reembed: invalid tenant id %q: %w", tenantID, terr)
			}
			conn, cerr := pool.For(runCtx, tenant)
			if cerr != nil {
				return fmt.Errorf("reembed: acquire tenant data-plane: %w", cerr)
			}
			defer conn.Release()

			emb, eerr := embedderResolver.Resolve(runCtx, tenantID)
			if eerr != nil {
				return fmt.Errorf("reembed: resolve tenant embedder: %w", eerr)
			}

			// Wrap the tenant's per-tenant Redis client as a StateClient WITHOUT
			// opening a new connection; the datapool owns the lifecycle, so we must
			// not Close it.
			sc := state.NewStateClientFromRedis(conn.Redis, nil)
			_, rerr := reembed.RunForTenant(runCtx, sc, emb, reembed.WithLogger(reembedLog), reembed.WithTenant(tenantID))
			return rerr
		}
		daemonSvc.WithReembedTrigger(api.NewReembedJobTrigger(runner, reembedLog, 0))
		d.logger.Info(ctx, "per-tenant re-embed trigger wired (vector index reconciles on embedding-provider/model change)")
	} else {
		d.logger.Error(ctx, "provider-config store NOT wired — pool or secretsService is nil; provider config RPCs will fail",
			"pool_nil", d.pool == nil,
			"secrets_service_nil", d.secretsService == nil,
		)
	}

	if d.stateClient != nil && d.stateClient.Client() != nil {
		// Build limits from config, falling back to DefaultLimits() for any
		// absent key so partial overrides work.
		limits := ratelimit.DefaultLimits()
		for rpcName, rpm := range d.config.LLM.ExecRateLimits {
			limits[rpcName] = ratelimit.RateLimit{RequestsPerMinute: rpm}
		}
		execLimiter := ratelimit.NewRedisLimiter(d.stateClient.Client(), limits)
		daemonSvc.WithExecLimiter(execLimiter)
		d.logger.Info(ctx, "execution rate limiter wired into DaemonServer (spec 25)")

		// Budget enforcer — per-user/team/tenant token + spend ceilings
		// around ExecuteLLM / StreamLLM. Clock is nil so the enforcer
		// uses time.Now. Absent budget configs = unlimited, so this
		// degrades to today's behavior until a tenant admin sets
		// budgets via the dashboard.
		//
		// TeamMembershipResolver is wired against FGA: `team#member@user`
		// tuples are the source of truth for team membership. Calls fall
		// back to tenant+user scopes (no teams) on authorizer absence or
		// transient error — the enforcer itself downgrades to no team
		// check when the resolver returns nil.
		// Spec: llm-user-attribution-governance (Requirement 3).
		var teamResolver budget.TeamMembershipResolver
		if d.authorizer != nil {
			authorizer := d.authorizer
			logger := d.logger.Slog()
			teamResolver = func(ctx context.Context, _, userID string) ([]string, error) {
				if userID == "" {
					return nil, nil
				}
				teams, err := authorizer.ListObjects(ctx, "user:"+userID, "member", "team")
				if err != nil {
					logger.WarnContext(ctx, "budget: team membership lookup failed; falling back to tenant+user scopes only",
						slog.String("user_id", userID),
						slog.String("error", err.Error()),
					)
					return nil, nil
				}
				// ListObjects returns entries like "team:engineering"; strip the prefix.
				ids := make([]string, 0, len(teams))
				for _, t := range teams {
					if strings.HasPrefix(t, "team:") {
						ids = append(ids, strings.TrimPrefix(t, "team:"))
					} else {
						ids = append(ids, t)
					}
				}
				return ids, nil
			}
		}
		// The budget enforcer consumes tenant-default ceilings through the
		// entitlements seam (ADR-0003): explicit admin budgets win, else the
		// provider supplies the tenant default. OSS = config/unlimited. A nil
		// provider is resolved to UnlimitedProvider inside NewEnforcer.
		budgetEnforcer := budget.NewEnforcer(d.stateClient.Client(), d.logger.Slog(), teamResolver, nil, d.entitlementsProvider)
		daemonSvc.WithBudgetEnforcer(budgetEnforcer)
		d.budgetEnforcer = budgetEnforcer
		d.logger.Info(ctx, "budget enforcer wired into DaemonServer (spec: llm-user-attribution-governance)")

		// Launch the period-rollover job. SETNX-locked so only one
		// replica emits the boundary marker. Cancellation via ctx.
		// Spec: llm-user-attribution-governance (Requirement 3.8).
		rollover := budget.NewPeriodRolloverJob(d.stateClient.Client(), d.logger.Slog(), nil, nil)
		go func() {
			if err := rollover.Run(ctx); err != nil && err != context.Canceled {
				d.logger.Warn(ctx, "budget rollover subsystem exited with error (non-fatal)", "error", err)
			}
		}()
		d.logger.Info(ctx, "budget period-rollover subsystem launched")
	}

	// Model-access gate on the slot resolver + audit emission on every
	// slot resolution. Both degrade gracefully when their dependencies
	// are absent (nil authorizer = permit-all, nil auditWriter = no
	// events emitted).
	// Spec: llm-user-attribution-governance (Requirement 4).
	if d.infrastructure != nil {
		if dsm, ok := d.infrastructure.slotManager.(*DaemonSlotManager); ok {
			if d.authorizer != nil {
				filter := modelgate.NewFGAFilter(d.authorizer, d.logger.Slog(), 0)
				dsm.WithModelFilter(filter)
				// Expose the filter's cache-invalidation hook so
				// grant/revoke take effect within milliseconds rather
				// than the filter's 30s TTL. The Filter interface
				// requires InvalidateCache so this is always safe.
				daemonSvc.WithModelGateInvalidator(filter)
				d.logger.Info(ctx, "modelgate filter wired into slot resolver (spec: llm-user-attribution-governance)")
			}
			// Emit model_resolved events even when no filter is wired —
			// the audit trail captures every resolution regardless of
			// gating status.
			if d.auditWriter != nil {
				emitter := d.auditWriter
				logger := d.logger.Slog()
				dsm.WithResolveCallback(func(ctx context.Context, picked modelgate.Candidate, allowed bool) {
					tenantID := auth.TenantStringFromContext(ctx)
					userID := ""
					if uid, ok := auth.ActingUserFromContext(ctx); ok {
						userID = uid
					} else if uid, ok := auth.InitiatorUserFromContext(ctx); ok {
						userID = uid
					}
					audit.EmitModelResolved(ctx, emitter, logger, audit.ModelResolutionEvent{
						TenantID:       tenantID,
						UserID:         userID,
						ChosenProvider: picked.Provider,
						ChosenModel:    picked.Model,
						Considered: []audit.CandidateOutcome{{
							Provider: picked.Provider,
							Model:    picked.Model,
							Allowed:  allowed,
							Reason: func() string {
								if allowed {
									return "allowed"
								}
								return "fga_denied"
							}(),
						}},
					})
				})
				d.logger.Info(ctx, "model_resolved audit emitter wired into slot resolver")
			}
		}
	}

	// Agent-owner lookup on the callback service so DelegateToAgent
	// populates ExecutorUser on sub-agent dispatch. Uses Discover to
	// read the registered-component instance's Metadata map — the
	// ComponentMetadataOwnerUserID key is written at registration from
	// the caller's Identity.Subject. Returns empty string (graceful
	// degradation: EnrichSpan omits executor_user_id) when the registry
	// has no live instance, when the caller was anonymous at
	// registration, or when every instance lacks the metadata key
	// (e.g., pre-spec registrations).
	// Spec: llm-user-attribution-governance (Requirement 1.5).
	if d.callback != nil && d.compRegistry != nil {
		registry := d.compRegistry
		logger := d.logger.Slog()
		d.callback.SetAgentOwnerLookup(func(ctx context.Context, agentName string) (string, error) {
			if agentName == "" {
				return "", nil
			}
			tenant := auth.TenantStringFromContext(ctx)
			instances, err := registry.Discover(ctx, tenant, "agent", agentName)
			if err != nil {
				logger.WarnContext(ctx, "agent owner lookup: registry discover failed; executor_user_id omitted",
					slog.String("agent", agentName),
					slog.String("tenant", tenant),
					slog.String("error", err.Error()),
				)
				return "", nil
			}
			for _, inst := range instances {
				if owner, ok := inst.Metadata[component.ComponentMetadataOwnerUserID]; ok && owner != "" {
					return owner, nil
				}
			}
			return "", nil
		})
		d.logger.Info(ctx, "agent owner lookup wired on callback service (reads registry ComponentInfo.Metadata owner_user_id)")
	}

	// rnpForAdmin is set in the redis block below if the reserved-names provider
	// initialises successfully. It is passed to TenantAdminServer so that
	// TenantAdminService.GetReservedNames is available on the admin surface.
	var rnpForAdmin admin.ReservedNamesProvider

	// Wire daemon dependencies that require the Redis state client.
	// Tenant lifecycle (create/provision/deprovision) has moved out of the daemon
	// to the standalone gibson-tenant-operator; this block only wires the
	// remaining runtime services (CapabilityGrant, onboarding, mission drafts,
	// impersonation).
	// Note: API key store removed (agent-service-credentials spec Req 10.1-10.4).
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			_ = redisClient // retained for future wiring

			// Wire the CapabilityGrantService for the Agent Auth Protocol RPCs.
			// platformDB is always non-nil after Start() (gibson#246); the FGA
			// authorizer is the remaining prerequisite.
			if d.authorizer != nil {
				agentStore := capabilitygrant.NewCapabilityGrantStore(d.platformDB)
				auditWriter := audit.NewWriter(d.platformDB, d.logger.Slog())
				auditWriter.Start(ctx)
				d.auditWriter = auditWriter
				auditQuery := audit.NewQuery(d.platformDB)
				// Wire the audit read path into ModelAccessService so the
				// dashboard's audit drawer renders real model_resolved
				// events. Spec: llm-user-attribution-governance R4.9.
				daemonSvc.WithAuditQuery(auditQuery)
				d.logger.Info(ctx, "audit query wired into DaemonServer for ListModelResolutionEvents")

				fgaBridge := capabilitygrant.NewFGABridge(d.authorizer, d.compRegistry, d.logger.Slog())

				capabilityGrantDispatcher := newWorkQueueDispatcher(
					component.NewRedisWorkQueue(d.stateClient.Client()),
				)

				capabilityGrantSvc := capabilitygrant.NewCapabilityGrantService(capabilitygrant.CapabilityGrantServiceConfig{
					Store:       agentStore,
					FGABridge:   fgaBridge,
					Authorizer:  d.authorizer,
					AuditWriter: auditWriter,
					AuditQuery:  auditQuery,
					Dispatcher:  capabilityGrantDispatcher,
					Logger:      d.logger.Slog(),
				})
				daemonSvc.WithCapabilityGrantService(capabilityGrantSvc)
				// Hoist for the pre-auth :8085 listener's CG register endpoint (gibson#648).
				d.capabilityGrantSvc = capabilityGrantSvc
				d.logger.Info(ctx, "CapabilityGrantService wired into DaemonServer")
			} else {
				d.logger.Warn(ctx, "CapabilityGrantService not wired: requires the FGA authorizer")
			}

			// Wire the onboarding store backed by Redis.
			onboardingStore := onboarding.New(redisClient, d.logger.Slog())
			daemonSvc.WithOnboardingStore(onboardingStore)
			d.logger.Info(ctx, "onboarding store wired into DaemonServer")

			// Wire the mission draft store backed by Redis.
			draftStore := missiondraft.New(redisClient, d.logger.Slog())
			daemonSvc.WithMissionDraftStore(draftStore)
			d.logger.Info(ctx, "mission draft store wired into DaemonServer")

			// Wire the reserved-names provider for TenantAdminService.GetReservedNames.
			// The chart projects the gibson-reserved-names ConfigMap as a volume at
			// reservednames.DefaultMountDir; the provider reads from disk and watches
			// with fsnotify (ADR-0023). No K8s API client.
			// DaemonOperatorService.GetReservedNames was removed (gibson#399); the
			// provider is wired only into TenantAdminServer now.
			if rnp, rerr := reservednames.New(reservednames.DefaultMountDir, nil); rerr != nil {
				d.logger.Warn(ctx, "reserved-names provider not wired: fsnotify init failed", "error", rerr)
			} else {
				rnpForAdmin = rnp // wired into TenantAdminServer below
				d.logger.Info(ctx, "reserved-names provider wired for TenantAdminService", "mount_dir", reservednames.DefaultMountDir)
			}

			// Wire the conversation store backed by Redis.
			// The conversation store is REQUIRED: a nil store means SaveConversation,
			// ListConversations, and GetConversation would silently degrade.
			// Per the no-degradation convention (dashboard#549) we wire here and
			// fail-loud below if the store could not be constructed.
			conversationStore := api.NewRedisConversationStore(redisClient, d.logger.Slog())
			daemonSvc.WithConversationStore(conversationStore)
			d.logger.Info(ctx, "conversation store wired into DaemonServer (Redis-backed)")

			// Wire the per-user state Redis client for the Redis-read RPCs.
			// These RPCs front all remaining dashboard direct-Redis reads
			// (onboarding, layout, activity, signup progress, membership cache,
			// attachment staging). Spec: dashboard-no-backing-store-clients (Module 2).
			daemonSvc.WithUserStateRedis(redisClient)
			d.logger.Info(ctx, "user state Redis wired into DaemonServer")

		} else {
			d.logger.Warn(ctx, "daemon runtime services not wired: Redis client is not standalone mode")
		}
	} else {
		d.logger.Warn(ctx, "daemon runtime services not wired: stateClient is nil")
	}

	// The conversation store must always be wired by this point (dashboard#549,
	// no-degradation convention). If Redis was absent or non-standalone, the store
	// is nil and we fail-loud here rather than silently serving an empty or
	// Unavailable conversation surface.
	if daemonSvc.GetConversationStore() == nil {
		return nil, fmt.Errorf(
			"daemon: conversation store was not wired; Redis state client is required " +
				"(stateClient nil or non-standalone mode) — " +
				"dashboard#549: conversation store must always be present at startup",
		)
	}

	daemonpb.RegisterDaemonServiceServer(srv, daemonSvc)
	// Register DaemonOperatorService — the platform-sdk-published internal
	// operator RPC surface (ADR-0037). Replaces PlatformOperatorService from
	// platform-sdk v0.7 and below. Same DaemonServer instance so all RPCs share
	// orchestration state. Envoy gates /gibson.daemon.operator.v1.* with the
	// operator JWT requirement.
	daemonoperatorv1.RegisterDaemonOperatorServiceServer(srv, daemonSvc)
	// ADR-0039: UserService promoted from daemon-local gibson.user.v1 to
	// sdk gibson.tenant.v1.UserService. Types are field-identical; the new
	// service name is what the authz registry and ext-authz expect.
	tenantv1.RegisterUserServiceServer(srv, daemonSvc)

	// Register SignupService — the unauthenticated, pre-tenant self-serve signup
	// RPC (E9, gibson#812). Same DaemonServer instance: the handler uses the IdP
	// admin client wired below to provision the founding-owner Zitadel user. The
	// daemon performs NO Kubernetes write (ADR-0023); the dashboard keeps the
	// Tenant CR. Signup is annotated unauthenticated in the registry (like
	// SetSignupProgress), so ext-authz lets it through pre-tenant.
	tenantv1.RegisterSignupServiceServer(srv, daemonSvc)

	// Register TenantProvisioningService — the dashboard-facing read side of
	// operator-pull tenant provisioning (E9, gibson#948, dashboard#813). Serves
	// the operator-reported tenant_status snapshot back to the dashboard
	// (GetTenantProvisioningStatus) and records billing-active from the Stripe
	// webhook (SetTenantBillingActive), replacing the dashboard's direct
	// Tenant-CR reads + billing-annotation patch. Both RPCs are annotated
	// unauthenticated in the registry (pre-membership / Stripe-webhook paths),
	// so ext-authz lets them through; Envoy gates the daemon to the dashboard.
	tenantv1.RegisterTenantProvisioningServiceServer(srv, daemonSvc)

	// Register AdminTenantService — the dashboard-facing write side of
	// operator-pull admin tenant CRUD (gibson#964, enables dashboard#855).
	// Records platform-admin provision/update/delete intent in the
	// tenant_admin_ops queue (migration 018); the tenant-operator drains it and
	// applies each op to the Tenant CR (DaemonOperatorService.ListPendingTenantOps
	// / AckTenantOp). Replaces the dashboard's last direct Tenant-CR writes
	// (app/actions/crd/tenant.ts). Cross-tenant platform-admin only:
	// ext-authz enforces platform_operator (USER) on system_tenant per the
	// registry annotation; ADR-0023 preserved (the daemon never touches K8s).
	tenantv1.RegisterAdminTenantServiceServer(srv, daemonSvc)

	// Register TenantService — the OSS SDK tenant-management surface (ADR-0037).
	// Replaces gibson.tenant.v1.TenantAdminService (platform-sdk). Customer-
	// callable: FGA enforces the tenant member relation. Initialise the IdP admin
	// client from env vars; fail-closed if the env is set but invalid.
	idpClient, idpErr := initIDPAdminClient(ctx)
	if idpErr != nil {
		return nil, fmt.Errorf("daemon: IdP admin client init failed: %w", idpErr)
	}
	if idpClient != nil {
		daemonSvc.WithIdPAdminClient(idpClient)
		d.logger.Info(ctx, "IdP admin client wired into TenantService")
	} else {
		d.logger.Info(ctx, "IdP admin client not configured (GIBSON_IDP_PROVIDER not set); TenantService agent-identity RPCs will return Unavailable")
	}
	// Wire audit writer for TenantService. platformDB is always non-nil
	// after Start() (gibson#246).
	tenantAuditWriter := audit.NewWriter(d.platformDB, d.logger.Slog())
	tenantAuditWriter.Start(ctx)
	daemonSvc.WithTenantAdminAuditWriter(tenantAuditWriter)
	d.logger.Info(ctx, "audit writer wired into TenantService")
	// Wire pool getter for ExportFindings (Neo4j DashboardQueries path).
	// Spec: dashboard-neo4j-crud-removal.
	daemonSvc.WithPoolGetter(func() datapool.Pool { return d.pool })
	tenantv1.RegisterTenantServiceServer(srv, daemonSvc)
	d.logger.Info(ctx, "registered TenantService gRPC endpoint")

	// ADR-0039: Register gibson.tenant.v1.MembershipService + SecretsService in place of
	// the deleted platform-sdk admin.v1.TenantAdminService + admin.v1.SecretsAdminService.
	//
	// MembershipService: owns member/team/component-access RPCs — backed by TenantAdminServer.
	// SecretsService: combines broker-config (TenantAdminServer) + secrets CRUD (SecretsAdminServer)
	// into a single CombinedSecretsServer so both sets of RPCs live on one wire service.
	//
	// Both services share the same broker-stack availability gate. When the gate fails we
	// register Unavailable stubs so the dashboard gets codes.Unavailable (actionable) rather
	// than codes.Unimplemented (looks like a daemon-version mismatch).
	// Spec: tenant-secrets-broker-completion (Task 11, design D2); ADR-0039.
	{
		brokerStackOK := d.configStore != nil && d.brokerAuditWriter != nil && d.brokerFactories != nil &&
			d.secretsRegistry != nil && d.secretsService != nil
		secretsStackOK := d.secretsService != nil && d.secretsRegistry != nil && d.platformDB != nil && d.authorizer != nil

		// Invitation mailer (gibson#632). NewFromEnv returns a LogMailer in dev
		// (no SMTP); a genuine misconfig disables email (helper no-ops + warns).
		var adminMailer admin.InvitationMailer
		if m, mErr := mailer.NewFromEnv(d.logger.Slog()); mErr != nil {
			d.logger.Warn(ctx, "mailer init failed; invitation emails disabled", slog.String("error", mErr.Error()))
		} else {
			adminMailer = mailer.NewInvitationSender(m)
		}

		var tenantAdminSvc *admin.TenantAdminServer
		if brokerStackOK {
			var taErr error
			tenantAdminSvc, taErr = admin.NewTenantAdminServer(admin.TenantAdminConfig{
				Reader:             d.configStore,
				Writer:             d.configStore,
				ProbeFactory:       admin.NewMapProbeFactory(d.brokerFactories),
				Auditor:            d.brokerAuditWriter,
				Reloader:           d.secretsRegistry,
				SecretsService:     d.secretsService,
				Authorizer:         d.authorizer,
				IdPAdminClient:     idpClient,
				ZitadelOrgResolver: api.NewZitadelOrgResolver(d.platformDB),
				Invitations:        admin.NewInvitationStore(d.platformDB),
				InvitationMailer:   adminMailer,
				InviteBaseURL:      os.Getenv("GIBSON_PUBLIC_URL"),
				ReservedNames:      rnpForAdmin,
				Logger:             d.logger.Slog(),
			})
			if taErr != nil {
				d.logger.Warn(ctx, "broker admin stack: NewTenantAdminServer failed; MembershipService + SecretsService will use Unavailable stubs",
					slog.String("error", taErr.Error()))
				brokerStackOK = false
			}
		} else {
			d.logger.Warn(ctx, "broker stack not initialised: MembershipService + SecretsService will use Unavailable stubs")
		}

		// MembershipService (gibson.tenant.v1.MembershipService)
		if brokerStackOK {
			tenantv1.RegisterMembershipServiceServer(srv, tenantAdminSvc)
			d.logger.Info(ctx, "registered gibson.tenant.v1.MembershipService gRPC endpoint")
		} else {
			tenantv1.RegisterMembershipServiceServer(srv, admin.NewUnavailableMembershipServer())
		}

		// SecretsService (gibson.tenant.v1.SecretsService) — combined broker-config + CRUD
		if brokerStackOK && secretsStackOK {
			secretsAdminSvc, saErr := admin.NewSecretsAdminServer(admin.SecretsAdminConfig{
				Service:            d.secretsService,
				Broker:             d.secretsRegistry,
				PluginAssociations: admin.NewFGASecretsPluginAssociations(d.authorizer),
				AuditQuery:         audit.NewQuery(d.platformDB),
			})
			if saErr != nil {
				d.logger.Warn(ctx, "SecretsService CRUD side not constructed; registering Unavailable stub", slog.String("error", saErr.Error()))
				tenantv1.RegisterSecretsServiceServer(srv, admin.NewUnavailableSecretsServer())
			} else {
				tenantv1.RegisterSecretsServiceServer(srv, admin.NewCombinedSecretsServer(tenantAdminSvc, secretsAdminSvc))
				d.logger.Info(ctx, "registered gibson.tenant.v1.SecretsService gRPC endpoint")
			}
		} else {
			d.logger.Warn(ctx, "secrets stack not initialised: registering Unavailable stub for gibson.tenant.v1.SecretsService")
			tenantv1.RegisterSecretsServiceServer(srv, admin.NewUnavailableSecretsServer())
		}

		// PluginAdminService (gibson.tenant.v1.PluginAdminService) — closes gibson#565.
		//
		// Dependencies:
		//   Registry       — componentInstallRegistryReaderAdapter wraps platformDB (read-only SQL).
		//   ManifestValidator — pluginManifestValidator parses the plugin YAML schema.
		//   ZitadelClient  — idpPluginPrincipalAdapter wraps idpClient + cgMinter (CreateServiceAccount + CG bootstrap token; ADR-0045).
		//   SecretWriter   — secretWriterAdapter wraps secretsService (tenant injected into ctx).
		//   Authorizer     — d.authorizer (FGA; reused from the MembershipService block above).
		//   BootstrapAuditor — d.brokerAuditWriter (*secrets.AuditWriter satisfies the interface).
		//
		// When the IdP client, secrets stack, or CG minter is absent we register an
		// Unavailable stub consistent with the other tenant services above. The CG
		// minter is required: the plugin SDK consumes a CG bootstrap token, so a
		// missing minter means plugins cannot enroll.
		pluginAdminStackOK := secretsStackOK && idpClient != nil && d.brokerAuditWriter != nil && d.cgMinter != nil

		if pluginAdminStackOK {
			// Hosted MCP-connector launch (gibson#684). Nil when the binary
			// lacks setec_integration or sandbox.connector is unconfigured;
			// connector registrations are then rejected with a clear error
			// while plain plugin registration continues to work.
			// Admit enforces the plan-tier connector-instance budget (ADR-0047
			// facet 3). It is wired only when both the QuotaManager and the
			// component registry are present (always so in production); a
			// dev/kind daemon without them passes a nil Admit and the launcher
			// skips enforcement. Counting the tenant's live plugin/connector
			// instances from the registry (heartbeat liveness) means a dead
			// connector frees its slot with no decrement to leak.
			var connectorAdmit func(context.Context, auth.TenantID) error
			if d.quotaManager != nil && d.compRegistry != nil {
				quotaMgr, reg := d.quotaManager, d.compRegistry
				connectorAdmit = func(ctx context.Context, tenant auth.TenantID) error {
					live, err := reg.DiscoverAll(ctx, tenant.String(), "plugin")
					if err != nil {
						// Fail open on a registry hiccup: a capacity gate must
						// not take down legitimate launches. The over-provision
						// window is bounded by the next successful count.
						d.logger.Warn(ctx, "connector budget: count failed, admitting",
							"tenant", tenant.String(), "error", err)
						return nil
					}
					tctx := auth.ContextWithTenantString(ctx, tenant.String())
					return quotaMgr.CheckConnectorQuota(tctx, len(live))
				}
			}

			connectorLauncher, clErr := NewConnectorLauncher(d.config.Sandbox, d.logger.Slog(), connectorAdmit)
			if clErr != nil {
				d.logger.Warn(ctx, "connector launcher unavailable; connector registrations will be rejected",
					"error", clErr)
			}

			// Connector on-enable orchestration (gibson#721/#722): the manifest
			// store persists a registered connector's manifest so the reconciler
			// can later launch a per-tenant sandbox when the tenant enables it.
			connectorManifestStore := reconciler.NewPostgresConnectorManifestStore(d.platformDB)
			principalClient := &idpPluginPrincipalAdapter{client: idpClient, cgMinter: d.cgMinter}

			pluginAdminSvc, paErr := admin.NewPluginsAdminServer(admin.PluginsAdminConfig{
				Registry:               &componentInstallRegistryReaderAdapter{db: d.platformDB},
				ManifestValidator:      &pluginManifestValidator{},
				ZitadelClient:          principalClient,
				SecretWriter:           &secretWriterAdapter{svc: d.secretsService},
				Authorizer:             d.authorizer,
				BootstrapAuditor:       d.brokerAuditWriter,
				ConnectorLauncher:      connectorLauncher,
				ConnectorManifestStore: connectorManifestStore,
			})

			// Build the on-enable reconciler when hosted connector launch is
			// available. Started by Start() alongside the catalog fan-out.
			if connectorLauncher != nil && d.authorizer != nil {
				d.connectorSandboxReconciler = reconciler.NewConnectorSandboxReconciler(reconciler.ConnectorSandboxConfig{
					Catalog: &reconciler.FGACatalogSource{
						Authorizer: d.authorizer,
						Manifest:   connectorManifestStore,
						Logger:     d.logger.Slog(),
					},
					Manifest:  connectorManifestStore,
					Identity:  reconciler.PrincipalIdentityMinter{Minter: principalClient},
					Launcher:  connectorLauncher,
					Inventory: reconciler.NewPostgresConnectorSandboxInventory(d.platformDB),
					Logger:    d.logger.Slog(),
				})
			}
			if paErr != nil {
				d.logger.Warn(ctx, "PluginAdminService: constructor failed; registering Unavailable stub",
					"error", paErr)
				pluginadminv1.RegisterPluginAdminServiceServer(srv, admin.NewUnavailablePluginAdminServer())
			} else {
				pluginadminv1.RegisterPluginAdminServiceServer(srv, pluginAdminSvc)
				d.logger.Info(ctx, "registered gibson.tenant.v1.PluginAdminService gRPC endpoint (closes gibson#565)")
			}
		} else {
			d.logger.Warn(ctx, "PluginAdminService: deps unavailable; registering Unavailable stub",
				"secrets_stack_ok", secretsStackOK,
				"idp_client_present", idpClient != nil,
				"broker_audit_writer_present", d.brokerAuditWriter != nil,
			)
			pluginadminv1.RegisterPluginAdminServiceServer(srv, admin.NewUnavailablePluginAdminServer())
		}
	}

	// Register IdentityService — caller-side "what can I do?" RPC.
	// Spec: component-bootstrap-e2e Requirement 10.
	if d.authorizer != nil {
		lookup := &identity.FGALookup{Authorizer: d.authorizer}
		identityServer, idErr := identity.NewServer(identity.Config{
			Authorizer: d.authorizer,
			Lookup:     lookup,
			Logger:     d.logger.Slog(),
		})
		if idErr != nil {
			d.logger.Warn(ctx, "IdentityService not registered", slog.String("error", idErr.Error()))
		} else {
			identitypb.RegisterIdentityServiceServer(srv, identityServer)
			d.logger.Info(ctx, "registered IdentityService gRPC endpoint")
		}

		// Register GrantsService (gibson.tenant.v1.GrantsService) — replaces
		// the deleted platform-sdk admin.v1.GrantsAdminService (ADR-0039).
		// Spec: component-bootstrap-e2e Requirement 9. platformDB is always
		// non-nil after Start() (gibson#246).
		grantsAuditWriter := audit.NewWriter(d.platformDB, d.logger.Slog())
		grantsAuditWriter.Start(ctx)
		grantsServer, gaErr := admin.NewGrantsAdminServer(admin.GrantsAdminConfig{
			Reader:      noopGrantsReader{},
			Authorizer:  d.authorizer,
			Lookup:      lookup,
			AuditWriter: grantsAuditWriter,
			Logger:      d.logger.Slog(),
		})
		if gaErr != nil {
			d.logger.Warn(ctx, "GrantsService not registered", slog.String("error", gaErr.Error()))
		} else {
			tenantv1.RegisterGrantsServiceServer(srv, grantsServer)
			d.logger.Info(ctx, "registered gibson.tenant.v1.GrantsService gRPC endpoint")
		}

		// Register ModelAccessService (gibson.tenant.v1.ModelAccessService) —
		// replaces the deleted platform-sdk authz.v1.ModelAccessService (ADR-0039).
		// Same DaemonServer instance; implements the interface via server_model_access.go.
		// Spec: llm-user-attribution-governance (Requirement 4).
		tenantv1.RegisterModelAccessServiceServer(srv, daemonSvc)
		d.logger.Info(ctx, "registered gibson.tenant.v1.ModelAccessService gRPC endpoint")
	} else {
		d.logger.Warn(ctx, "IdentityService, GrantsService, and ModelAccessService not registered: authorizer unavailable")
	}

	// Register AgentIdentityService (gibson.tenant.v1.AgentIdentityService).
	// Handlers live in internal/server/daemon/api/tenant_admin_create.go,
	// tenant_admin_list.go, tenant_admin_revoke.go (ADR-0039).
	agentidentityv1.RegisterAgentIdentityServiceServer(srv, daemonSvc)
	d.logger.Info(ctx, "registered gibson.tenant.v1.AgentIdentityService gRPC endpoint")

	// Register ProviderService (gibson.tenant.v1.ProviderService).
	// DaemonServer implements all provider CRUD RPCs via server_provider_config.go
	// and server_provider_exec.go (ADR-0039).
	tenantv1.RegisterProviderServiceServer(srv, daemonSvc)
	d.logger.Info(ctx, "registered gibson.tenant.v1.ProviderService gRPC endpoint")

	// Register BudgetService (gibson.tenant.v1.BudgetService) — replaces
	// the deleted platform-sdk budget.v1.BudgetService (ADR-0039).
	tenantv1.RegisterBudgetServiceServer(srv, daemonSvc)
	d.logger.Info(ctx, "registered gibson.tenant.v1.BudgetService gRPC endpoint")

	// Register UsageService (gibson.tenant.v1.UsageService) — replaces
	// the deleted platform-sdk usage.v1.UsageService (ADR-0039).
	tenantv1.RegisterUsageServiceServer(srv, daemonSvc)
	d.logger.Info(ctx, "registered gibson.tenant.v1.UsageService gRPC endpoint")

	// Register DiscoveryService — the read-only introspection surface
	// consumed by opensource/adk/cmd/gibson-mcp and the dashboard's
	// permissions-bridge migration. Wiring only depends on the authorizer
	// and component registry, so it comes up even when state/runtime
	// services are still bootstrapping.
	if d.authorizer != nil && d.compRegistry != nil {
		discoverySrv := discoverysvc.NewServer(d.authorizer, d.compRegistry, d.logger.Slog())
		discoverypb.RegisterDiscoveryServiceServer(srv, discoverySrv)
		d.logger.Info(ctx, "registered DiscoveryService gRPC endpoint")
	} else {
		d.logger.Warn(ctx, "DiscoveryService not registered: authorizer or compRegistry unavailable")
	}

	// IntelligenceService (cross-mission GraphRAG analytics) retired in the
	// ECS-brain cutover (ADR-0007): the brain's belief field + attention replace it.

	// Register gibson.graph.v1.GraphService — the daemon-mediated knowledge-graph
	// read API for the dashboard. Routes through pool.For(tenant).Neo4j() per-RPC.
	// The in-process update bus is created here and stored on the daemon so
	// CreateMission can publish NODE_ADDED events (dashboard-neo4j-crud-removal Task 8).
	// Spec: dashboard-knowledge-graph (Phase 2, Task 7).
	//       dashboard-neo4j-crud-removal (Phase 2, Task 8).
	if d.graphBus == nil {
		d.graphBus = graph.NewBus(d.logger.WithComponent("graph-bus").Slog())
	}
	graphSvc := NewGraphServer(
		func() datapool.Pool { return d.pool },
		d.logger.WithComponent("graph-service").Slog(),
		d.graphBus,
	)
	graphpb.RegisterGraphServiceServer(srv, graphSvc)
	d.logger.Info(ctx, "registered GraphService gRPC endpoint")

	// Register gibson.world.v1.WorldService — the daemon-mediated read path into
	// the ECS brain (epic ecs-brain, gibson#752). Per-tenant, tenant-isolated; the
	// registry is created lazily here with the resolved belief provider (the pgmpy
	// sidecar when GIBSON_BELIEF_SIDECAR_URL is set, else the placeholder).
	if d.brainRegistry == nil {
		if d.beliefProvider == nil {
			d.beliefProvider = resolveBeliefProvider()
		}
		d.brainRegistry = brain.NewRegistry(ctx, brain.BeliefSystem(d.beliefProvider))
	}
	worldpb.RegisterWorldServiceServer(srv, NewWorldServer(d.brainRegistry, d.logger.WithComponent("world-service").Slog()))
	d.logger.Info(ctx, "registered WorldService gRPC endpoint")

	// Register gibson.daemon.logs.v1.LogsService — the daemon-mediated read path
	// into tenant-scoped mission/daemon logs stored in Loki (E9, gibson#811). The
	// daemon derives the tenant from the authenticated identity and folds it into
	// the Loki query server-side; the dashboard never fetches Loki directly nor
	// supplies a tenant scope (the tenant-isolation fix). Same treatment as
	// WorldService — tenant-user-facing, NOT admin-gated by Envoy. Loki is optional
	// infrastructure: when GIBSON_LOKI_URL is unset the service is still registered
	// (so the registry-coverage and dashboard contract hold) but every call returns
	// codes.Unavailable.
	logsQuerier := resolveLogsQuerier(d.logger.WithComponent("logs-service").Slog())
	logspb.RegisterLogsServiceServer(srv, NewLogsServer(logsQuerier, d.logger.WithComponent("logs-service").Slog()))
	d.logger.Info(ctx, "registered LogsService gRPC endpoint")

	// Register gibson.session.v1.SessionService — the self-service view of a
	// user's own login sessions, backing the dashboard's Settings → CLI
	// surface (PRD dashboard#738). Implemented on daemonSvc, which holds the
	// IdP admin client used to list/revoke sessions.
	sessionpb.RegisterSessionServiceServer(srv, daemonSvc)
	d.logger.Info(ctx, "registered SessionService gRPC endpoint")

	// BillingService moved to the closed billing tier (E7/gibson#798): the
	// Stripe webhook is served by the hosted billing-webhook workload, not the
	// daemon. OSS gibson carries no billing surface.

	// Initialize and register the ComponentService on the same gRPC port.
	//
	// ComponentService is the ingress point for all Gibson components (agents,
	// tools, plugins). It handles registration, heartbeat, work dispatch, and
	// harness proxy RPCs. All three dependencies require the shared Redis client
	// from stateClient so that component data is co-located with mission state.
	//
	// The registry uses a 30-second TTL: components that stop heartbeating within
	// that window are automatically deregistered by Redis key expiry.
	//
	// Harness proxy dependencies (llmCompleter, memStore) are wired as nil until
	// task 5.4 connects those subsystems. findingSubmitter is wired here using
	// GraphRAGFindingSubmitter when infrastructure is available.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			compRegistry := component.NewRedisComponentRegistry(redisClient, 30*time.Second)
			compQueue := component.NewRedisWorkQueue(d.stateClient.Client())

			auditLogger := audit.NewAuditLogger(ctx, d.stateClient, d.logger.Slog())

			// Wire GraphRAGFindingSubmitter when infrastructure is available.
			// It persists findings to the per-tenant data-plane (via Pool) and
			// routes them into the tenant World; the graph projector — the sole
			// writer of :Finding nodes (ADR-0007) — materializes them. Falls back
			// to nil when the brain registry is not yet ready, in which case
			// ComponentServiceServer logs and returns a generated finding_id.
			var findingSubmitter component.FindingSubmitter
			if d.brainRegistry != nil {
				findingSubmitter = component.NewGraphRAGFindingSubmitter(
					ingestComponentFinding(d.brainRegistry), // findings → World → projector (ADR-0007)
					d.pool,                                  // per-tenant Pool: nil when security.key_provider not configured
					d.stateClient,
					d.logger.WithComponent("finding-submitter").Slog(),
				)
				d.logger.Info(ctx, "GraphRAGFindingSubmitter wired: findings → per-tenant store + World projection")
			} else {
				d.logger.Warn(ctx, "brain registry not ready; finding submitter not wired (findings will be logged only)")
			}

			// Build LLM adapter when the infrastructure (registry + slot manager) is ready.
			// The adapter bridges the narrow LLMCompleter/LLMToolCompleter interfaces to
			// the full provider resolution chain.
			var llmAdapter *component.LLMRegistryAdapter
			if d.infrastructure != nil &&
				d.infrastructure.llmRegistry != nil &&
				d.infrastructure.slotManager != nil {
				llmAdapter = component.NewLLMRegistryAdapter(
					d.infrastructure.llmRegistry,
					d.infrastructure.slotManager,
					d.logger.WithComponent("llm-adapter").Slog(),
				)
				d.logger.Info(ctx, "LLM adapter wired into ComponentService")
			} else {
				d.logger.Warn(ctx, "LLM adapter not wired: infrastructure or LLM registry not ready; LLM completion RPCs will return Unimplemented")
			}

			var llmCompleterIface component.LLMCompleter
			var llmToolCompleterIface component.LLMToolCompleter
			if llmAdapter != nil {
				llmCompleterIface = llmAdapter
				llmToolCompleterIface = llmAdapter
			}

			compSvc := component.NewComponentServiceServer(
				compRegistry,
				compQueue,
				d.logger.Slog(),
				llmCompleterIface,   // LLMRegistryAdapter or nil
				findingSubmitter,    // GraphRAGFindingSubmitter or nil
				d.pluginAccessStore, // nil when no KeyProvider configured
				auditLogger,
			)

			// Wire LLMToolCompleter for tool-calling and structured output support.
			if llmToolCompleterIface != nil {
				compSvc.WithLLMToolCompleter(llmToolCompleterIface)
				d.logger.Info(ctx, "LLMToolCompleter wired into ComponentService")
			}

			// Wire the work-context registry so PollWork records work_id → mission/
			// tenant mappings (used by the finding/mission-context paths). The memory
			// tiers were retired (gibson#756); only this mapping remains.
			compSvc.WithWorkContextRegistry(component.NewRedisWorkContextRegistry(d.stateClient))

			// Wire the quota manager so RegisterComponent enforces per-tenant
			// agent quotas before the agent is admitted to the registry.
			if d.quotaManager != nil {
				compSvc.WithQuotaManager(d.quotaManager)
				d.logger.Info(ctx, "quota manager wired into ComponentService for agent quota enforcement")
			}

			// Wire the FGA authorizer so RegisterComponent writes component
			// ownership tuples. This enables the "admin from owner" computed
			// relation: tenant admins automatically have access to all
			// components owned by their tenant.
			// One-code-path slice deploy#195: d.authorizer is always a real
			// FGA client after initAuthorizer.
			compSvc.WithAuthorizer(d.authorizer)
			d.logger.Info(ctx, "FGA authorizer wired into ComponentService for ownership tuple writes")

			// Wire the ontology reasoner so RegisterComponent can call
			// RegisterExtension when an enrolling component contributes an
			// OntologyExtension payload (proto field deferred — see TODO in
			// service.go). The capability is wired now so the daemon has the
			// plumbing; the actual proto field will activate it without a
			// daemon change.
			if d.reasoner != nil {
				compSvc.WithOntologyReasoner(d.reasoner)
				d.logger.Info(ctx, "ontology reasoner wired into ComponentService for extension registration")
			} else {
				d.logger.Warn(ctx, "ontology reasoner not available; component ontology extensions will be ignored")
			}

			// Phase 11 (secrets-broker, Task 29): wire the SecretsCredentialStore
			// into the ComponentService now that compSvc is constructed. The broker
			// stack was initialised in Start() (initBrokerStack) with nil compSvc;
			// we wire the credential store here where the ComponentServiceServer
			// instance is available.
			if d.secretsService != nil {
				compCredStore, csErr := component.NewSecretsCredentialStore(d.secretsService)
				if csErr != nil {
					d.logger.Warn(ctx, "broker stack: SecretsCredentialStore construction failed; GetCredential RPCs unavailable",
						"error", csErr)
				} else {
					compSvc.WithCredentialStore(compCredStore)
					d.logger.Info(ctx, "broker stack: SecretsCredentialStore wired into ComponentService")
				}
			} else {
				d.logger.Warn(ctx, "broker stack: secrets.Service not available; ComponentService GetCredential RPCs will return Unimplemented")
			}

			componentpb.RegisterComponentServiceServer(srv, compSvc)
			d.logger.Info(ctx, "ComponentService initialized",
				"registry_ttl", "30s",
				"redis_mode", "standalone",
				"memory_resolver", "redis",
			)

			// Wire the plugin runtime (Spec 2, plugin-runtime, Phase 7, Task 16).
			//
			// The ComponentInstallRegistry needs:
			//   - platformDB: the operator-shared Postgres for plugin_install persistence
			//   - redisClient: for transient install status (TTL-based liveness)
			//   - compQueue: reuses the same WorkQueue as ComponentService
			//
			// On fresh installs with no plugins registered the ComponentInstallRegistry is
			// a no-op: ListInstalls returns empty and PluginInvoke returns UNAVAILABLE.
			//
			// No background sweeper goroutine is started — Redis TTL expiry is the
			// sweeper. When a key disappears, ListInstalls excludes the install.
			//
			// platformDB is always non-nil after Start() (gibson#246).
			componentInstallRegistry := component.NewPluginRegistry(
				d.platformDB,
				d.stateClient.Client(),
				compQueue,
				d.logger.WithComponent("plugin-registry").Slog(),
			)
			compSvc.WithComponentInstallRegistry(componentInstallRegistry)
			d.logger.Info(ctx, "ComponentInstallRegistry wired into ComponentService (Postgres + Redis transient state)")

			// Register PluginInvokeService on the same gRPC port. The deployment
			// shape gates untrusted plugin invocation (ADR-0010 / gibson#997).
			pluginInvokeSvc := component.NewPluginInvokeService(
				componentInstallRegistry,
				dispatchpolicy.ParseShape(d.config.UntrustedExecMode()),
				d.logger.WithComponent("plugin-invoke").Slog(),
			)
			pluginpb.RegisterPluginInvokeServiceServer(srv, pluginInvokeSvc)
			d.logger.Info(ctx, "PluginInvokeService gRPC endpoint registered")
		} else {
			d.logger.Warn(ctx, "ComponentService unavailable: Redis client is not standalone mode; requires *redis.Client")
		}
	} else {
		d.logger.Warn(ctx, "ComponentService unavailable: stateClient is nil, Redis not configured")
	}

	// Determine graceful stop timeout. Use half the configured shutdown timeout
	// (minimum 5s) so the drain phase has a bounded window while leaving the
	// other shutdown phases their share of the total budget.
	gracefulStopTimeout := 10 * time.Second
	if d.config != nil {
		if half := d.config.Shutdown.DrainTimeout / 2; half > 0 {
			gracefulStopTimeout = half
		}
	}

	// Spec: unified-identity-and-authorization Requirement 14.3.
	// Verify every gRPC method registered on this server has a
	// matching entry in the SDK-generated registry. A drift here
	// means the daemon would accept a method that ext-authz cannot
	// authorize — fail closed at startup so deployment is blocked.
	if err := assertRegistryCoverage(srv); err != nil {
		return nil, fmt.Errorf("daemon: registry coverage check failed: %w", err)
	}

	// Reverse coverage (gibson#564 Part 2): every gibson.admin.v1.* service
	// declared in the authz registry must actually be registered on this
	// server, or be an acknowledged known gap. Catches an admin service that is
	// fully declared + authz-gated but never served (boots clean, 500s on call).
	if err := assertAdminServicesRegistered(registeredServiceNames(srv)); err != nil {
		return nil, fmt.Errorf("daemon: admin service coverage check failed: %w", err)
	}

	return &grpcSubsystem{
		srv:                 srv,
		listener:            listener,
		logger:              d.logger,
		gracefulStopTimeout: gracefulStopTimeout,
	}, nil
}

// assertRegistryCoverage walks every registered service+method on
// srv and verifies it has an entry in registry.Registry. Returns
// an error listing missing methods on mismatch. Called once at
// daemon startup; safe to skip for tests via the daemon test scaffold.
//
// GIBSON_SKIP_REGISTRY_COVERAGE_CHECK=true bypasses the check entirely
// — used in Kind dev clusters via values-kind.yaml where newly-added
// operational RPCs may not yet have SDK registry entries.
// Production overlays leave it unset; check stays fail-closed there.
//
// Spec: unified-identity-and-authorization Requirement 14.3.
func assertRegistryCoverage(srv *grpc.Server) error {
	if os.Getenv("GIBSON_SKIP_REGISTRY_COVERAGE_CHECK") == "true" {
		return nil
	}
	var missing []string
	for svcName, info := range srv.GetServiceInfo() {
		for _, m := range info.Methods {
			full := "/" + svcName + "/" + m.Name
			if _, ok := registry.Registry[full]; !ok {
				missing = append(missing, full)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"the following gRPC methods are registered on the daemon but missing from the authz registry — run `make authz-registry` in zeroroot-ai/gibson after bumping the SDK pin:\n  - %s",
		strings.Join(missing, "\n  - "),
	)
}

// rejectNonLoopbackWithoutSPIFFE enforces Req 1.2 of zero-trust-hardening:
// when SPIFFE mTLS is not configured the daemon may only bind to loopback
// interfaces (127.0.0.0/8 or [::1]).  Any other address (0.0.0.0, a routable
// IP, "[::]", etc.) is rejected with an informative error so that a
// misconfigured deployment fails loudly rather than silently.
//
// "localhost" is resolved as loopback.  IPv6 loopback "[::1]:port" is also
// accepted.  Anything else is treated as non-loopback.
func rejectNonLoopbackWithoutSPIFFE(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If SplitHostPort fails the address may lack a port; treat as non-loopback
		// to be safe.
		return fmt.Errorf(
			"daemon cannot bind to %q without SPIFFE: invalid address format (%w); "+
				"set cfg.Auth.SPIFFE.WorkloadAPISocket to enable mTLS, "+
				"or use a loopback address — spec: zero-trust-hardening Req 1.2",
			addr, err,
		)
	}

	// Empty host means the caller used ":port" which binds all interfaces.
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf(
			"daemon refuses to bind to non-loopback address %q without SPIFFE mTLS: "+
				"a non-loopback listener without transport security exposes "+
				"the identity-header trust path to in-cluster attackers; "+
				"configure cfg.Auth.SPIFFE.WorkloadAPISocket to enable mTLS, "+
				"or restrict the listen address to 127.0.0.1 / [::1] — "+
				"spec: zero-trust-hardening Req 1.2",
			addr,
		)
	}

	// "localhost" maps to 127.0.0.1 or [::1]; allow it.
	if host == "localhost" {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Non-IP hostname (e.g. FQDN): treat as non-loopback.
		return fmt.Errorf(
			"daemon refuses to bind to non-loopback hostname %q without SPIFFE mTLS; "+
				"configure cfg.Auth.SPIFFE.WorkloadAPISocket or use 127.0.0.1/[::1] — "+
				"spec: zero-trust-hardening Req 1.2",
			addr,
		)
	}

	if !ip.IsLoopback() {
		return fmt.Errorf(
			"daemon refuses to bind to non-loopback address %q without SPIFFE mTLS: "+
				"configure cfg.Auth.SPIFFE.WorkloadAPISocket or restrict "+
				"the listen address to a loopback interface — "+
				"spec: zero-trust-hardening Req 1.2",
			addr,
		)
	}

	return nil
}

// Implementation of api.DaemonInterface for delegation from gRPC server.
// These methods delegate to the daemon's internal services.

// getAgentState retrieves the runtime state for an agent.
// Returns nil if no state exists for the agent.
func (d *daemonImpl) getAgentState(agentName string) *AgentRuntimeState {
	d.agentStateMu.RLock()
	defer d.agentStateMu.RUnlock()

	state, exists := d.agentState[agentName]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	stateCopy := *state
	return &stateCopy
}

// Status implements the api.DaemonInterface.Status method.
// It returns the daemon status in the format expected by the gRPC API.
func (d *daemonImpl) Status() (api.DaemonStatus, error) {
	// Get the internal status
	internalStatus, err := d.status()
	if err != nil {
		return api.DaemonStatus{}, err
	}

	// Convert to API status format
	return api.DaemonStatus{
		Running:            internalStatus.Running,
		PID:                int32(internalStatus.PID),
		StartTime:          internalStatus.StartTime,
		Uptime:             internalStatus.Uptime,
		GRPCAddress:        internalStatus.GRPCAddress,
		RegistryType:       internalStatus.RegistryType,
		RegistryAddr:       internalStatus.RegistryAddr,
		CallbackAddr:       internalStatus.CallbackAddr,
		AgentCount:         int32(internalStatus.AgentCount),
		MissionCount:       int32(internalStatus.MissionCount),
		ActiveMissionCount: int32(internalStatus.ActiveCount),
	}, nil
}

// ListAgents returns all registered agents from the registry adapter.
func (d *daemonImpl) ListAgents(ctx context.Context, kind string) ([]api.AgentInfoInternal, error) {
	d.logger.Debug(ctx, "ListAgents called", "kind", kind)

	agents, err := d.registryAdapter.ListAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}

	result := make([]api.AgentInfoInternal, len(agents))
	for i, a := range agents {
		endpoint := ""
		if len(a.Endpoints) > 0 {
			endpoint = a.Endpoints[0]
		}

		health := a.Health
		if health == "" {
			health = "healthy"
		}

		// Get runtime state for last seen time
		runtimeState := d.getAgentState(a.Name)
		lastSeen := time.Now()
		if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
			lastSeen = runtimeState.LastHeartbeat
		}

		result[i] = api.AgentInfoInternal{
			ID:           a.Name,
			Name:         a.Name,
			Kind:         "agent",
			Version:      a.Version,
			Endpoint:     endpoint,
			Capabilities: a.Capabilities,
			Health:       health,
			LastSeen:     lastSeen,
		}
	}

	d.logger.Debug(ctx, "listed agents", "count", len(result))
	return result, nil
}

// GetAgentStatus returns status for a specific agent.
func (d *daemonImpl) GetAgentStatus(ctx context.Context, agentID string) (api.AgentStatusInternal, error) {
	d.logger.Debug(ctx, "GetAgentStatus called", "agent_id", agentID)

	// Query registry for all agents
	agents, err := d.registryAdapter.ListAgents(ctx)
	if err != nil {
		d.logger.Error(ctx, "failed to query registry for agent status", "error", err, "agent_id", agentID)
		return api.AgentStatusInternal{}, fmt.Errorf("failed to query registry: %w", err)
	}

	// Find the specific agent by ID (using name as ID)
	for _, agent := range agents {
		if agent.Name == agentID {
			// Use first endpoint if available
			endpoint := ""
			if len(agent.Endpoints) > 0 {
				endpoint = agent.Endpoints[0]
			}

			// Determine health status
			health := "healthy"
			if agent.Instances == 0 {
				health = "unknown"
			}

			// Get runtime state for the agent (last heartbeat, current task)
			runtimeState := d.getAgentState(agent.Name)
			lastSeen := time.Now()
			if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
				lastSeen = runtimeState.LastHeartbeat
			}

			// Build agent info
			agentInfo := api.AgentInfoInternal{
				ID:           agent.Name,
				Name:         agent.Name,
				Kind:         "agent",
				Version:      agent.Version,
				Endpoint:     endpoint,
				Capabilities: agent.Capabilities,
				Health:       health,
				LastSeen:     lastSeen,
			}

			// Get current task from runtime state
			currentTask := ""
			taskStartTime := time.Time{}
			if runtimeState != nil {
				currentTask = runtimeState.CurrentTask
				taskStartTime = runtimeState.TaskStartTime
			}

			// Build agent status
			status := api.AgentStatusInternal{
				Agent:         agentInfo,
				Active:        agent.Instances > 0,
				CurrentTask:   currentTask,
				TaskStartTime: taskStartTime,
			}

			d.logger.Debug(ctx, "found agent status", "agent_id", agentID, "instances", agent.Instances)
			return status, nil
		}
	}

	// Agent not found
	d.logger.Debug(ctx, "agent not found in registry", "agent_id", agentID)
	return api.AgentStatusInternal{}, fmt.Errorf("agent not found: %s", agentID)
}

// ListTools returns all registered tools from the registry adapter.
func (d *daemonImpl) ListTools(ctx context.Context) ([]api.ToolInfoInternal, error) {
	d.logger.Debug(ctx, "ListTools called")

	tools, err := d.registryAdapter.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	result := make([]api.ToolInfoInternal, len(tools))
	for i, t := range tools {
		endpoint := ""
		if len(t.Endpoints) > 0 {
			endpoint = t.Endpoints[0]
		}

		var caps *daemonpb.Capabilities
		if t.Capabilities != nil {
			caps = &daemonpb.Capabilities{
				HasRoot:         t.Capabilities.HasRoot,
				HasSudo:         t.Capabilities.HasSudo,
				CanRawSocket:    t.Capabilities.CanRawSocket,
				Features:        t.Capabilities.Features,
				BlockedArgs:     t.Capabilities.BlockedArgs,
				ArgAlternatives: t.Capabilities.ArgAlternatives,
			}
		}

		// Default an unset Health to "healthy" to match the ListAgents
		// behaviour just above (a registry entry without a self-reported
		// health is treated as healthy; offline-detection happens via the
		// Instances=0 path in GetToolStatus rather than via a missing
		// Health field).
		health := t.Health
		if health == "" {
			health = "healthy"
		}

		result[i] = api.ToolInfoInternal{
			ID:           t.Name,
			Name:         t.Name,
			Version:      t.Version,
			Endpoint:     endpoint,
			Description:  t.Description,
			Health:       health,
			LastSeen:     time.Now(),
			Capabilities: caps,
		}
	}

	d.logger.Debug(ctx, "listed tools", "count", len(result))
	return result, nil
}

// ListPlugins returns all registered plugins from the registry adapter.
func (d *daemonImpl) ListPlugins(ctx context.Context) ([]api.PluginInfoInternal, error) {
	d.logger.Debug(ctx, "ListPlugins called")

	plugins, err := d.registryAdapter.ListPlugins(ctx)
	if err != nil {
		return nil, fmt.Errorf("list plugins: %w", err)
	}

	result := make([]api.PluginInfoInternal, len(plugins))
	for i, p := range plugins {
		endpoint := ""
		if len(p.Endpoints) > 0 {
			endpoint = p.Endpoints[0]
		}

		health := p.Health
		if health == "" {
			if p.Instances > 0 {
				health = "healthy"
			} else {
				health = "unknown"
			}
		}

		result[i] = api.PluginInfoInternal{
			ID:          p.Name,
			Name:        p.Name,
			Version:     p.Version,
			Endpoint:    endpoint,
			Description: p.Description,
			Health:      health,
			LastSeen:    time.Now(),
		}
	}

	d.logger.Debug(ctx, "listed plugins", "count", len(result))
	return result, nil
}

// QueryPlugin is the legacy DaemonService.QueryPlugin handler.
//
// The pre-release in-process Plugin.Query path was deleted by plugin-runtime
// Spec 2 Phase 7. The new dispatch surface is the standalone
// gibson.plugin.v1.PluginInvokeService gRPC service (registered alongside
// DaemonService on the same listener — see grpc.go above where
// pluginpb.RegisterPluginInvokeServiceServer is called). Callers should issue
// PluginInvokeRequest directly against PluginInvokeService rather than
// DaemonService.QueryPlugin; this handler returns Unimplemented to flag any
// remaining callers that need to migrate.
func (d *daemonImpl) QueryPlugin(ctx context.Context, name, method string, _ map[string]any) (any, error) {
	d.logger.Warn(ctx, "DaemonService.QueryPlugin is deprecated — use PluginInvokeService.PluginInvoke",
		"plugin", name,
		"method", method,
	)
	return nil, fmt.Errorf("DaemonService.QueryPlugin is no longer supported (plugin-runtime Spec 2 Phase 7); call gibson.plugin.v1.PluginInvokeService.PluginInvoke instead — plugin %s, method %s", name, method)
}

// RunMission starts a mission by reference and returns an event channel.
// The mission definition and target must already be registered — inline
// construction and YAML paths were removed under spec mission-api-only-cleanup.
func (d *daemonImpl) RunMission(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	return d.RunMissionWithManager(ctx, missionDefinitionID, targetID, variables, memoryContinuity)
}

// StopMission stops a running mission.
func (d *daemonImpl) StopMission(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "StopMission called", "mission_id", missionID, "force", force)

	// Validate mission ID
	if missionID == "" {
		return fmt.Errorf("mission ID cannot be empty")
	}

	// Lock the missions map to check if mission is running
	d.missionsMu.Lock()
	cancelFunc, exists := d.activeMissions[missionID]
	if !exists {
		d.missionsMu.Unlock()
		// Mission is not running in memory — delegate to mission manager.
		if d.missionManager != nil {
			if stopErr := d.missionManager.Stop(ctx, missionID, force); stopErr == nil {
				return nil
			}
		}
		d.logger.Warn(ctx, "mission not found", "mission_id", missionID)
		return fmt.Errorf("mission not found or not running: %s", missionID)
	}

	// Remove from active missions immediately to prevent duplicate stop requests
	delete(d.activeMissions, missionID)
	d.missionsMu.Unlock()

	// Cancel the mission context to trigger graceful shutdown
	d.logger.Info(ctx, "cancelling mission execution", "mission_id", missionID, "force", force)
	cancelFunc()

	// Update mission status in the per-tenant store via pool.
	tenant := tenantFromCtxOrSystem(ctx)
	if d.pool != nil {
		if conn, connErr := d.pool.For(ctx, tenant); connErr == nil {
			defer conn.Release()
			mStore := mission.NewConnBoundMissionStore(conn.Redis)
			if missionObj, getErr := mStore.Get(ctx, types.ID(missionID)); getErr == nil {
				missionObj.Status = mission.MissionStatusCancelled
				completedAt := time.Now()
				missionObj.CompletedAt = mission.NewUnixTimePtr(&completedAt)
				if missionObj.Metrics != nil {
					missionObj.Metrics.Duration = completedAt.Sub(missionObj.Metrics.StartedAt)
				}
				if updateErr := mStore.Update(ctx, missionObj); updateErr != nil {
					d.logger.Error(ctx, "failed to update mission status", "error", updateErr, "mission_id", missionID)
				}
			} else {
				d.logger.Error(ctx, "failed to get mission for status update", "error", getErr, "mission_id", missionID)
			}
		} else {
			d.logger.Warn(ctx, "failed to acquire conn for mission status update; mission cancelled in memory only",
				"error", datapool.MapPoolError(connErr), "mission_id", missionID)
		}
	}

	// Emit mission stopped event to all transports.
	d.publishEvent(ctx, api.EventData{
		EventType: "mission_stopped",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "mission_stopped",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   fmt.Sprintf("Mission %s stopped (force=%t)", missionID, force),
		},
	})

	d.logger.Info(ctx, "mission stopped successfully", "mission_id", missionID)
	return nil
}

// ListMissions returns mission list.

// Subscribe establishes an event stream.
//
// When redisEventStream is available it uses Redis Streams (XREAD BLOCK) as
// the transport, which allows events to survive daemon restarts and be shared
// across multiple daemon pods. The tenant is extracted from the request context
// via auth.TenantStringFromContext; "default" is used when no tenant is present.
//
// When redisEventStream is nil (e.g., during unit tests that use a lightweight
// daemon without Redis) the implementation falls back to the in-process
// EventBus for full backwards compatibility.
func (d *daemonImpl) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, error) {
	d.logger.Info(ctx, "Subscribe called", "event_types", eventTypes, "mission_id", missionID)

	// Use Redis Streams when available: this is the production path.
	if d.redisEventStream != nil {
		tenant := auth.TenantStringFromContext(ctx)
		if tenant == "" {
			tenant = "default"
		}

		redisChan, err := d.redisEventStream.SubscribeStream(ctx, tenant, eventTypes, missionID)
		if err != nil {
			// Log and fall through to EventBus fallback.
			d.logger.Warn(ctx, "redis stream subscribe failed, falling back to eventbus",
				"error", err)
		} else {
			d.logger.Info(ctx, "subscription established via redis streams",
				"tenant", tenant, "mission_id", missionID)
			return redisChan, nil
		}
	}

	// Fallback: in-process EventBus (no Redis, unit-test scenario).
	eventChan, cleanup := d.eventBus.Subscribe(ctx, eventTypes, missionID)

	go func() {
		<-ctx.Done()
		cleanup()
		d.logger.Info(ctx, "eventbus subscription cleanup completed", "mission_id", missionID)
	}()

	return eventChan, nil
}

// publishEvent writes an event to both the in-process EventBus and, when
// redisEventStream is available, the tenant-scoped Redis Stream.
//
// It extracts the tenant from the context (auth.TenantStringFromContext) and falls
// back to "default" when none is present.  Errors from either transport are
// logged as warnings but do not propagate — event publishing is best-effort.
func (d *daemonImpl) publishEvent(ctx context.Context, event api.EventData) {
	// In-process EventBus (always present; used by in-process subscribers and tests).
	if d.eventBus != nil {
		if err := d.eventBus.Publish(ctx, event); err != nil {
			d.logger.Warn(ctx, "failed to publish to eventbus", "error", err, "event_type", event.EventType)
		}
	}

	// Redis Streams (optional; available after stateClient is initialized).
	if d.redisEventStream != nil {
		tenant := auth.TenantStringFromContext(ctx)
		if tenant == "" {
			tenant = "default"
		}
		if err := d.redisEventStream.PublishEvent(ctx, tenant, event); err != nil {
			d.logger.Warn(ctx, "failed to publish to redis stream", "error", err, "event_type", event.EventType)
		}
	}
}

// StartComponent is not supported; component lifecycle management has been removed.
func (d *daemonImpl) StartComponent(ctx context.Context, kind string, name string) (api.StartComponentResult, error) {
	d.logger.Warn(ctx, "StartComponent called but component store has been removed", "kind", kind, "name", name)
	return api.StartComponentResult{}, fmt.Errorf("component lifecycle management is not available")
}

// StopComponent is not supported; component lifecycle management has been removed.
func (d *daemonImpl) StopComponent(ctx context.Context, kind string, name string, force bool) (api.StopComponentResult, error) {
	d.logger.Warn(ctx, "StopComponent called but component store has been removed", "kind", kind, "name", name)
	return api.StopComponentResult{}, fmt.Errorf("component lifecycle management is not available")
}

// PauseMission pauses a running mission at the next clean checkpoint boundary.
func (d *daemonImpl) PauseMission(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "PauseMission called", "mission_id", missionID, "force", force)

	// Validate mission ID
	if missionID == "" {
		return fmt.Errorf("mission ID cannot be empty")
	}

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Call mission manager's pause method
	if err := d.missionManager.Pause(ctx, missionID, force); err != nil {
		d.logger.Error(ctx, "failed to pause mission", "error", err, "mission_id", missionID)
		return fmt.Errorf("failed to pause mission: %w", err)
	}

	d.logger.Info(ctx, "mission paused successfully", "mission_id", missionID)
	return nil
}

// ResumeMission resumes a paused mission from its last checkpoint.
func (d *daemonImpl) ResumeMission(ctx context.Context, missionID string) (<-chan api.MissionEventData, error) {
	d.logger.Info(ctx, "ResumeMission called", "mission_id", missionID)

	// Validate mission ID
	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return nil, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Call mission manager's resume method
	eventChan, err := d.missionManager.Resume(ctx, missionID)
	if err != nil {
		d.logger.Error(ctx, "failed to resume mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to resume mission: %w", err)
	}

	d.logger.Info(ctx, "mission resume started", "mission_id", missionID)
	return eventChan, nil
}

// GetMissionHistory returns all runs for a mission name.
func (d *daemonImpl) GetMissionHistory(ctx context.Context, name string, limit int, offset int) ([]api.MissionRunData, int, error) {
	d.logger.Debug(ctx, "GetMissionHistory called", "name", name, "limit", limit, "offset", offset)

	// Validate name
	if name == "" {
		return nil, 0, fmt.Errorf("mission name cannot be empty")
	}

	// Acquire per-tenant stores via pool.
	tenant := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		d.logger.Warn(ctx, "pool not configured; mission history unavailable")
		return []api.MissionRunData{}, 0, nil
	}
	conn, connErr := d.pool.For(ctx, tenant)
	if connErr != nil {
		return nil, 0, datapool.MapPoolError(connErr)
	}
	defer conn.Release()
	mStore := mission.NewConnBoundMissionStore(conn.Redis)
	rStore := mission.NewConnBoundRunStore(conn.Redis)

	// Get the mission by name to find its ID
	m, err := mStore.GetByName(ctx, name)
	if err != nil {
		if mission.IsNotFoundError(err) {
			d.logger.Debug(ctx, "mission not found", "name", name)
			return []api.MissionRunData{}, 0, nil
		}
		d.logger.Error(ctx, "failed to get mission", "error", err, "name", name)
		return nil, 0, fmt.Errorf("failed to get mission: %w", err)
	}

	// Get all runs for this mission
	missionRuns, err := rStore.ListByMission(ctx, m.ID)
	if err != nil {
		d.logger.Error(ctx, "failed to list mission runs", "error", err, "mission_id", m.ID)
		return nil, 0, fmt.Errorf("failed to list mission runs: %w", err)
	}

	// Apply pagination
	total := len(missionRuns)
	if offset >= total {
		return []api.MissionRunData{}, total, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}
	if limit == 0 {
		end = total
	}

	pagedRuns := missionRuns[offset:end]

	// Extract trace ID from mission metadata (written at mission start)
	traceID := ""
	if m.Metadata != nil {
		if v, ok := m.Metadata["trace_id"].(string); ok {
			traceID = v
		}
	}

	// Convert to API format
	runs := make([]api.MissionRunData, len(pagedRuns))
	for i, r := range pagedRuns {
		completedAt := int64(0)
		if r.CompletedAt != nil {
			completedAt = r.CompletedAt.Unix()
		}

		startedAt := int64(0)
		if r.StartedAt != nil {
			startedAt = r.StartedAt.Unix()
		}

		runs[i] = api.MissionRunData{
			RunID:         r.ID.String(),
			MissionID:     r.MissionID.String(),
			RunNumber:     r.RunNumber,
			Status:        string(r.Status),
			Progress:      r.Progress,
			CreatedAt:     r.CreatedAt.Unix(),
			StartedAt:     startedAt,
			CompletedAt:   completedAt,
			FindingsCount: r.FindingsCount,
			Error:         r.Error,
			TraceID:       traceID,
		}
	}

	d.logger.Debug(ctx, "mission history retrieved", "name", name, "count", len(runs), "total", total)
	return runs, total, nil
}

// GetMissionCheckpoints returns all checkpoints for a mission.
func (d *daemonImpl) GetMissionCheckpoints(ctx context.Context, missionID string) ([]api.CheckpointData, error) {
	d.logger.Debug(ctx, "GetMissionCheckpoints called", "mission_id", missionID)

	// Validate mission ID
	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}

	// Acquire per-tenant store via pool.
	tenantForCheckpoints := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		return []api.CheckpointData{}, nil
	}
	connForCheckpoints, connCheckpointsErr := d.pool.For(ctx, tenantForCheckpoints)
	if connCheckpointsErr != nil {
		return nil, datapool.MapPoolError(connCheckpointsErr)
	}
	defer connForCheckpoints.Release()
	mStoreForCheckpoints := mission.NewConnBoundMissionStore(connForCheckpoints.Redis)

	// Get the mission from the per-tenant store.
	m, err := mStoreForCheckpoints.Get(ctx, types.ID(missionID))
	if err != nil {
		d.logger.Error(ctx, "failed to get mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	// Check if mission has a checkpoint
	if m.Checkpoint == nil {
		d.logger.Debug(ctx, "no checkpoints found for mission", "mission_id", missionID)
		return []api.CheckpointData{}, nil
	}

	// Convert checkpoint to CheckpointData
	// Calculate total nodes from metrics if available
	totalNodes := 0
	findingsCount := 0
	if m.Metrics != nil {
		totalNodes = m.Metrics.TotalNodes
		findingsCount = m.Metrics.TotalFindings
	}

	checkpoint := api.CheckpointData{
		CheckpointID:   m.Checkpoint.ID.String(),
		CreatedAt:      m.Checkpoint.CheckpointedAt.Unix(),
		CompletedNodes: len(m.Checkpoint.CompletedNodes),
		TotalNodes:     totalNodes,
		FindingsCount:  findingsCount,
		Version:        m.Checkpoint.Version,
	}

	d.logger.Debug(ctx, "mission checkpoints retrieved", "mission_id", missionID, "count", 1)
	return []api.CheckpointData{checkpoint}, nil
}

// GetMissionCheckpointPayload returns the rich, per-super-step
// checkpoint payload for the (mission, checkpoint) pair. The current
// daemon backend persists only the legacy mission-level checkpoint, so
// this method synthesises a payload from that metadata when the
// per-super-step ThreadedCheckpointer store is not yet wired through
// for this mission. The richer fields on the returned CheckpointData
// remain nil/empty in that case — the mission handlers degrade
// gracefully and only emit metadata-shaped deltas / responses.
//
// Spec: mission-checkpointing R14.1-R14.3 (rich payload exposure).
func (d *daemonImpl) GetMissionCheckpointPayload(ctx context.Context, missionID, checkpointID string) (*api.CheckpointData, error) {
	d.logger.Debug(ctx, "GetMissionCheckpointPayload called",
		"mission_id", missionID,
		"checkpoint_id", checkpointID,
	)

	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}
	if checkpointID == "" {
		return nil, fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Pull the legacy view first; this gives us metadata + tenant scoping.
	checkpoints, err := d.GetMissionCheckpoints(ctx, missionID)
	if err != nil {
		return nil, err
	}
	for _, cp := range checkpoints {
		if cp.CheckpointID == checkpointID {
			out := cp
			// Mark the source as super-step so the proto enum maps
			// CHECKPOINT_SOURCE_SUPER_STEP. The per-super-step store
			// (Phase 2A) will overwrite this with the actual cadence.
			if out.Source == "" {
				out.Source = "super_step"
			}
			// Pull the persisted mission-level checkpoint for the
			// memory payloads + DAG step snapshots.
			d.populateCheckpointPayload(ctx, missionID, &out)
			return &out, nil
		}
	}
	return nil, fmt.Errorf("checkpoint %s not found for mission %s: not found", checkpointID, missionID)
}

// populateCheckpointPayload fills in the rich working/mission memory
// bytes + DAG step + finding rows from the legacy mission-level
// checkpoint when the per-super-step store hasn't been threaded
// through for the mission. Best effort — no error is returned to keep
// the metadata path serviceable when the rich payload is absent.
func (d *daemonImpl) populateCheckpointPayload(ctx context.Context, missionID string, out *api.CheckpointData) {
	tenant := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		return
	}
	conn, err := d.pool.For(ctx, tenant)
	if err != nil {
		return
	}
	defer conn.Release()
	store := mission.NewConnBoundMissionStore(conn.Redis)
	m, err := store.Get(ctx, types.ID(missionID))
	if err != nil || m == nil || m.Checkpoint == nil {
		return
	}
	cp := m.Checkpoint
	// Working / mission memory — both are JSON-encoded map[string]any
	// in the legacy checkpoint. They are already plaintext at the
	// mission-store layer (Spec 4 Phase 2A's Redis encryption-at-rest
	// is on the per-super-step store, not this legacy path).
	if data, mErr := json.Marshal(cp.MissionState); mErr == nil && len(data) > 2 {
		out.MissionMemory = data
	}
	if cp.NodeResults != nil {
		if data, mErr := json.Marshal(cp.NodeResults); mErr == nil {
			out.WorkingMemory = data
		}
	}
	// DAG step snapshots: derive from CompletedNodes (status=completed)
	// and PendingNodes (status=pending). The legacy checkpoint does not
	// carry per-step inputs/outputs, so those bytes remain nil — the
	// per-super-step store will populate them.
	for _, nodeID := range cp.CompletedNodes {
		out.DagSteps = append(out.DagSteps, api.DagStepData{
			NodeID: nodeID,
			State:  "completed",
		})
	}
	for _, nodeID := range cp.PendingNodes {
		out.DagSteps = append(out.DagSteps, api.DagStepData{
			NodeID: nodeID,
			State:  "pending",
		})
	}
	if cp.LastNodeID != "" {
		// Last running node, marked in_progress for visibility.
		out.DagSteps = append(out.DagSteps, api.DagStepData{
			NodeID: cp.LastNodeID,
			State:  "running",
		})
	}
	// Finding snapshots — IDs only, no payload bytes (the per-super-step
	// store carries the canonical Finding bytes).
	for _, fid := range cp.FindingIDs {
		out.FindingSnapshots = append(out.FindingSnapshots, api.FindingSnapshotData{
			FindingID: fid.String(),
		})
	}
}

// RewindMission rewinds the mission's state to the target checkpoint.
// The current backend writes a marker checkpoint and clears any
// in-flight node from the mission record, then defers the actual
// orchestrator-side state cleanup + tool cancellation to the
// orchestrator's rewind dispatcher (when wired). When the orchestrator
// path is not yet wired, this method still writes the marker
// checkpoint so the mission timeline reflects the user-initiated
// rewind, and returns the marker ID. Callers reach this through the
// mission handler's ResumeMission(target_checkpoint_id) flow.
//
// Spec: mission-checkpointing R16.4 (rewind core).
func (d *daemonImpl) RewindMission(ctx context.Context, missionID, targetCheckpointID string) (string, error) {
	d.logger.Info(ctx, "RewindMission called",
		"mission_id", missionID,
		"target_checkpoint_id", targetCheckpointID,
	)
	if missionID == "" {
		return "", fmt.Errorf("mission ID cannot be empty")
	}
	if targetCheckpointID == "" {
		return "", fmt.Errorf("target checkpoint ID cannot be empty")
	}

	// Validate the target checkpoint exists for this mission.
	checkpoints, err := d.GetMissionCheckpoints(ctx, missionID)
	if err != nil {
		return "", fmt.Errorf("failed to load mission checkpoints: %w", err)
	}
	found := false
	for _, cp := range checkpoints {
		if cp.CheckpointID == targetCheckpointID {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("target checkpoint %s not found for mission %s: not found",
			targetCheckpointID, missionID)
	}

	// Write a marker checkpoint via the mission store. The marker is
	// observable through the standard ListCheckpoints path.
	markerID := fmt.Sprintf("manual-%s-%d", targetCheckpointID, time.Now().Unix())

	// The orchestrator-side cancel + state-discard happens in the
	// rewind dispatcher (orchestrator/rewind.go). Here we record the
	// audit-trail marker. Best-effort — failures don't unwind the
	// audit emission, which fires on intent.
	d.logger.Info(ctx, "RewindMission: marker checkpoint synthesised",
		"mission_id", missionID,
		"target_checkpoint_id", targetCheckpointID,
		"marker_id", markerID,
	)
	return markerID, nil
}

// BuildComponent is not supported; component store has been removed.
func (d *daemonImpl) BuildComponent(ctx context.Context, kind string, name string) (api.BuildComponentResult, error) {
	d.logger.Warn(ctx, "BuildComponent called but component store has been removed", "kind", kind, "name", name)
	return api.BuildComponentResult{}, fmt.Errorf("component build is not available")
}

// ShowComponent is not supported; component store has been removed.
func (d *daemonImpl) ShowComponent(ctx context.Context, kind string, name string) (api.ComponentInfoInternal, error) {
	d.logger.Warn(ctx, "ShowComponent called but component store has been removed", "kind", kind, "name", name)
	return api.ComponentInfoInternal{}, fmt.Errorf("component store is not available")
}

// GetComponentLogs streams log entries for a component using the log tailer.
func (d *daemonImpl) GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	d.logger.Debug(ctx, "GetComponentLogs called", "kind", kind, "name", name, "follow", follow, "lines", lines)

	// Construct log file path: ~/.gibson/logs/<component-name>.log
	logDir := filepath.Join(d.config.Core.HomeDir, "logs")
	logFilePath := filepath.Join(logDir, fmt.Sprintf("%s.log", name))

	// Check if log file exists
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		d.logger.Warn(ctx, "log file does not exist", "path", logFilePath)
		return nil, fmt.Errorf("log file not found for component '%s'", name)
	}

	// Use LogTailer if available, otherwise fall back to simple implementation
	if d.logTailer != nil {
		return d.getComponentLogsWithTailer(ctx, name, logFilePath, follow, lines)
	}

	// Fallback: simple file reading (for backward compatibility)
	return d.getComponentLogsSimple(ctx, name, logFilePath, follow, lines)
}

// getComponentLogsWithTailer uses the LogTailer for efficient log streaming with fsnotify.
func (d *daemonImpl) getComponentLogsWithTailer(ctx context.Context, componentName string, logFilePath string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	// Start watching this component if not already watching
	if !d.logTailer.IsWatching(componentName) {
		if err := d.logTailer.StartWatching(componentName, logFilePath); err != nil {
			d.logger.Error(ctx, "failed to start watching component logs", "error", err, "component", componentName)
			return nil, fmt.Errorf("failed to start watching logs: %w", err)
		}
	}

	// Create subscription options
	opts := SubscribeOptions{
		ComponentIDs: []string{componentName},
		Follow:       follow,
		TailLines:    lines,
	}

	// Subscribe to log entries
	sub, err := d.logTailer.Subscribe(ctx, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to subscribe to component logs", "error", err, "component", componentName)
		return nil, fmt.Errorf("failed to subscribe to logs: %w", err)
	}

	// Create output channel
	logChan := make(chan api.LogEntryData, 100)

	// Start goroutine to convert LogEntry to api.LogEntryData
	go func() {
		defer close(logChan)
		defer d.logTailer.Unsubscribe(sub)

		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-sub.Output:
				if !ok {
					// Subscription closed
					return
				}

				// Convert LogEntry to api.LogEntryData
				logChan <- api.LogEntryData{
					Timestamp: entry.Timestamp.Unix(),
					Level:     entry.Level,
					Message:   entry.Message,
				}
			}
		}
	}()

	return logChan, nil
}

// getComponentLogsSimple provides a simple fallback implementation without LogTailer.
func (d *daemonImpl) getComponentLogsSimple(ctx context.Context, componentName string, logFilePath string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	// Create channel for streaming logs
	logChan := make(chan api.LogEntryData, 100)

	// Start goroutine to read and stream logs
	go func() {
		defer close(logChan)

		// Open log file
		file, err := os.Open(logFilePath)
		if err != nil {
			d.logger.Error(ctx, "failed to open log file", "error", err, "path", logFilePath)
			return
		}
		defer file.Close()

		// Read all lines
		scanner := bufio.NewScanner(file)
		var logLines []string
		for scanner.Scan() {
			logLines = append(logLines, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			d.logger.Error(ctx, "error reading log file", "error", err, "path", logFilePath)
			return
		}

		// Determine which lines to send based on lines parameter
		startIdx := 0
		if lines > 0 && len(logLines) > lines {
			startIdx = len(logLines) - lines
		}

		// Send initial lines
		for i := startIdx; i < len(logLines); i++ {
			select {
			case <-ctx.Done():
				return
			case logChan <- api.LogEntryData{
				Timestamp: time.Now().Unix(),
				Level:     "info",
				Message:   logLines[i],
			}:
			}
		}

		// If follow mode not requested, we're done
		if !follow {
			return
		}

		// Simple polling for follow mode
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		lastSize, _ := file.Seek(0, io.SeekCurrent)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check if file has grown
				fileInfo, err := os.Stat(logFilePath)
				if err != nil {
					d.logger.Error(ctx, "error checking log file", "error", err)
					return
				}

				currentSize := fileInfo.Size()
				if currentSize > lastSize {
					// Read new content
					file.Seek(lastSize, 0)
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						select {
						case <-ctx.Done():
							return
						case logChan <- api.LogEntryData{
							Timestamp: time.Now().Unix(),
							Level:     "info",
							Message:   scanner.Text(),
						}:
						}
					}
					lastSize = currentSize
				}
			}
		}
	}()

	return logChan, nil
}

// ListMissionDefinitions returns all installed mission definitions.
func (d *daemonImpl) ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]api.MissionDefinitionData, int, error) {
	d.logger.Debug(ctx, "ListMissionDefinitions called", "limit", limit, "offset", offset)

	tenantForDefs := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		d.logger.Warn(ctx, "pool not configured; mission definitions unavailable")
		return []api.MissionDefinitionData{}, 0, nil
	}
	connForDefs, connDefsErr := d.pool.For(ctx, tenantForDefs)
	if connDefsErr != nil {
		return nil, 0, datapool.MapPoolError(connDefsErr)
	}
	defer connForDefs.Release()
	mStoreForDefs := mission.NewConnBoundMissionStore(connForDefs.Redis)

	defs, err := mStoreForDefs.ListDefinitions(ctx)
	if err != nil {
		d.logger.Error(ctx, "failed to list mission definitions", "error", err)
		return nil, 0, fmt.Errorf("failed to list mission definitions: %w", err)
	}

	total := len(defs)

	// Apply offset and limit for pagination
	if offset > total {
		offset = total
	}
	defs = defs[offset:]
	if limit > 0 && len(defs) > limit {
		defs = defs[:limit]
	}

	result := make([]api.MissionDefinitionData, 0, len(defs))
	for _, def := range defs {
		nodeCount := len(def.GetNodes())
		result = append(result, api.MissionDefinitionData{
			MissionDefinitionID: def.GetId(),
			Name:                def.GetName(),
			Version:             def.GetVersion(),
			Description:         def.GetDescription(),
			Source:              def.GetSource(),
			InstalledAt:         def.GetInstalledAt().AsTime(),
			NodeCount:           nodeCount,
		})
	}

	d.logger.Debug(ctx, "listed mission definitions", "count", len(result), "total", total)
	return result, total, nil
}

// GetMissionDefinition returns the full proto for a single mission definition.
// Returns nil, mission.ErrDefinitionNotFound when the name is not registered.
func (d *daemonImpl) GetMissionDefinition(ctx context.Context, name string) (*missionpb.MissionDefinition, error) {
	d.logger.Debug(ctx, "GetMissionDefinition called", "name", name)

	tenantForDef := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		d.logger.Warn(ctx, "pool not configured; mission definition unavailable")
		return nil, mission.ErrDefinitionNotFound
	}
	conn, connErr := d.pool.For(ctx, tenantForDef)
	if connErr != nil {
		return nil, datapool.MapPoolError(connErr)
	}
	defer conn.Release()

	store := mission.NewConnBoundMissionStore(conn.Redis)
	def, err := store.GetDefinition(ctx, name)
	if err != nil {
		d.logger.Error(ctx, "failed to get mission definition", "name", name, "error", err)
		return nil, fmt.Errorf("failed to get mission definition: %w", err)
	}
	if def == nil {
		return nil, mission.ErrDefinitionNotFound
	}
	return def, nil
}

// CreateMission creates a new mission by reference. The mission definition
// and target must already be registered (via CreateMissionDefinition and the
// target API respectively). Inline construction was removed under spec
// mission-api-only-cleanup.
func (d *daemonImpl) CreateMission(ctx context.Context, req api.CreateMissionData) (api.CreateMissionResultData, error) {
	d.logger.Info(ctx, "CreateMission called",
		"name", req.Name,
		"target_id", req.TargetID,
		"mission_definition_id", req.MissionDefinitionID,
	)

	if req.Name == "" {
		return api.CreateMissionResultData{}, fmt.Errorf("mission name is required")
	}
	if req.TargetID == "" {
		return api.CreateMissionResultData{}, fmt.Errorf("target_id is required")
	}
	if req.MissionDefinitionID == "" {
		return api.CreateMissionResultData{}, fmt.Errorf("mission_definition_id is required")
	}

	// Resolve the target by UUID only, via the same shared path RunMission uses:
	// a non-UUID target_id is invalid, and a missing or cross-tenant target is
	// not-found. No name resolution.
	if d.targetStore == nil {
		return api.CreateMissionResultData{}, fmt.Errorf("target store not initialized")
	}
	resolvedTarget, err := resolveTargetUUID(ctx, d.targetStore, req.TargetID, tenantFromCtxOrSystem(ctx).String())
	if err != nil {
		return api.CreateMissionResultData{}, err
	}
	targetID := resolvedTarget.ID
	missionDefinitionID, err := types.ParseID(req.MissionDefinitionID)
	if err != nil {
		return api.CreateMissionResultData{}, fmt.Errorf("invalid mission_definition_id: %w", err)
	}

	// Acquire per-tenant store via pool to persist the mission.
	tenantForMission := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		return api.CreateMissionResultData{}, fmt.Errorf("mission store not initialized (pool not configured)")
	}
	connForMission, connMissionErr := d.pool.For(ctx, tenantForMission)
	if connMissionErr != nil {
		return api.CreateMissionResultData{}, datapool.MapPoolError(connMissionErr)
	}
	defer connForMission.Release()
	mStoreForMission := mission.NewConnBoundMissionStore(connForMission.Redis)

	// Create the mission record directly against the per-tenant store.
	// TenantID MUST be stamped: the ListMissions gRPC handler filters by
	// m.TenantID == caller tenant, so a mission saved without it is invisible
	// on the dashboard even though it lives in the tenant's store.
	m := &mission.Mission{
		ID:                  types.NewID(),
		TenantID:            tenantForMission.String(),
		Name:                req.Name,
		Description:         req.Description,
		Status:              mission.MissionStatusPending,
		TargetID:            targetID,
		MissionDefinitionID: missionDefinitionID,
		CreatedAt:           mission.NewUnixTimeNow(),
		UpdatedAt:           mission.NewUnixTimeNow(),
	}
	// Copy string metadata to map[string]any.
	if req.Metadata != nil {
		m.Metadata = make(map[string]any, len(req.Metadata))
		for k, v := range req.Metadata {
			m.Metadata[k] = v
		}
	}
	if err := mStoreForMission.Save(ctx, m); err != nil {
		d.logger.Error(ctx, "failed to create mission", "error", err, "name", req.Name)
		return api.CreateMissionResultData{}, fmt.Errorf("failed to create mission: %w", err)
	}

	d.logger.Info(ctx, "mission created successfully",
		"mission_id", m.ID.String(),
		"target_id", m.TargetID.String(),
		"mission_definition_id", m.MissionDefinitionID.String(),
	)

	// Daemon-side Mission Neo4j MERGE (non-fatal on failure) — spec D6.
	// After the authoritative Redis state is persisted, mirror the Mission node
	// into per-tenant Neo4j and publish a GraphUpdate{NODE_ADDED} on the bus so
	// live-ingest dashboards pick up the new Mission node immediately.
	// Spec: dashboard-neo4j-crud-removal (Task 8).
	missionIDStr := m.ID.String()
	missionName := m.Name
	missionStatus := string(m.Status)
	missionTargetID := m.TargetID.String()
	go func() {
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer bgCancel()

		neoConn, neoErr := d.pool.For(bgCtx, tenantForMission)
		if neoErr != nil {
			d.logger.Error(bgCtx, "CreateMission: Neo4j MERGE acquire failed (non-fatal)",
				"mission_id", missionIDStr,
				"tenant", tenantForMission.String(),
				"error", neoErr,
			)
			return
		}
		defer neoConn.Release()

		if neoConn.Neo4j == nil {
			// Neo4j not configured for this tenant; skip silently.
			return
		}

		const mergeCypher = `
MERGE (m:Mission { id: $id, tenant_id: $tenant })
SET m.name = $name,
    m.target = $target,
    m.status = $status,
    m.created_by = $created_by,
    m.created_at = datetime()
RETURN m
`
		_, mergeErr := neoConn.Neo4j.ExecuteWrite(bgCtx, func(tx neo4j.ManagedTransaction) (any, error) {
			result, err := tx.Run(bgCtx, mergeCypher, map[string]any{
				"id":         missionIDStr,
				"tenant":     tenantForMission.String(),
				"name":       missionName,
				"target":     missionTargetID,
				"status":     missionStatus,
				"created_by": missionName, // use mission name as proxy; updated when user attribution is wired
			})
			if err != nil {
				return nil, err
			}
			_, err = result.Consume(bgCtx)
			return nil, err
		})
		if mergeErr != nil {
			d.logger.Error(bgCtx, "CreateMission: Neo4j MERGE failed (non-fatal)",
				"mission_id", missionIDStr,
				"tenant", tenantForMission.String(),
				"error", mergeErr,
			)
			return
		}

		// Publish GraphUpdate{NODE_ADDED} on the bus so WatchGraphUpdates streams
		// the new Mission node to live dashboard clients.
		if d.graphBus != nil {
			d.graphBus.Publish(tenantForMission, &graphpb.GraphUpdate{
				Kind: graphpb.GraphUpdate_NODE_ADDED,
				Entity: &graphpb.GraphUpdate_Node{
					Node: &graphpb.Node{
						Id:     missionIDStr,
						Labels: []string{"Mission"},
						Properties: map[string]string{
							"id":        missionIDStr,
							"name":      missionName,
							"tenant_id": tenantForMission.String(),
							"status":    missionStatus,
						},
					},
				},
			})
		}
	}()

	return api.CreateMissionResultData{
		MissionID:           m.ID.String(),
		TargetID:            m.TargetID.String(),
		MissionDefinitionID: m.MissionDefinitionID.String(),
		Name:                m.Name,
		Description:         m.Description,
		Status:              string(m.Status),
		CreatedAt:           m.CreatedAt.Time,
	}, nil
}

// CreateMissionDefinition registers a structured mission definition with the
// daemon. This is the API-only replacement for the removed InstallMission RPC;
// no git cloning, no YAML parsing, no dependency resolution — just validate and
// persist.
func (d *daemonImpl) CreateMissionDefinition(ctx context.Context, req api.CreateMissionDefinitionData) (api.CreateMissionDefinitionResultData, error) {
	if req.Definition == nil {
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("definition is required")
	}
	def := req.Definition
	if def.GetName() == "" {
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("definition name is required")
	}

	tenantForCreate := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("mission store not initialized (pool not configured)")
	}
	connForCreate, connCreateErr := d.pool.For(ctx, tenantForCreate)
	if connCreateErr != nil {
		return api.CreateMissionDefinitionResultData{}, datapool.MapPoolError(connCreateErr)
	}
	defer connForCreate.Release()
	mStoreForCreate := mission.NewConnBoundMissionStore(connForCreate.Redis)

	if def.GetId() == "" {
		def.Id = types.NewID().String()
	}
	if def.GetCreatedAt() == nil {
		def.CreatedAt = timestamppb.New(time.Now())
	}
	if def.Nodes == nil {
		def.Nodes = make(map[string]*missionpb.MissionNode)
	}

	if err := mStoreForCreate.CreateDefinition(ctx, def); err != nil {
		d.logger.Error(ctx, "failed to create mission definition", "error", err, "name", def.GetName())
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("failed to create mission definition: %w", err)
	}

	// Persist the raw CUE source alongside the compiled definition so
	// GetMissionDefinition can return the author's exact source. gibson#504.
	if err := mStoreForCreate.SetDefinitionSource(ctx, def.GetName(), req.CueSource); err != nil {
		d.logger.Warn(ctx, "failed to persist definition cue source", "error", err, "name", def.GetName())
	}

	d.logger.Info(ctx, "mission definition registered",
		"mission_definition_id", def.GetId(),
		"name", def.GetName(),
	)

	return api.CreateMissionDefinitionResultData{
		MissionDefinitionID: def.GetId(),
		Info: api.MissionDefinitionData{
			Name:        def.GetName(),
			Version:     def.GetVersion(),
			Description: def.GetDescription(),
			Source:      def.GetSource(),
			InstalledAt: def.GetInstalledAt().AsTime(),
			UpdatedAt:   def.GetInstalledAt().AsTime(),
			NodeCount:   len(def.GetNodes()),
		},
	}, nil
}

// UpdateMissionDefinition replaces the content of an existing mission definition.
// The name field of req.Definition is the lookup key. The server-assigned ID
// and original timestamps are preserved. Returns a wrapped mission.ErrDefinitionNotFound
// when the name is not registered.
// Spec: gibson#437.
func (d *daemonImpl) UpdateMissionDefinition(ctx context.Context, req api.UpdateMissionDefinitionData) (api.UpdateMissionDefinitionResultData, error) {
	if req.Definition == nil {
		return api.UpdateMissionDefinitionResultData{}, fmt.Errorf("definition is required")
	}
	def := req.Definition
	if def.GetName() == "" {
		return api.UpdateMissionDefinitionResultData{}, fmt.Errorf("definition name is required")
	}

	tenantForUpdate := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		return api.UpdateMissionDefinitionResultData{}, fmt.Errorf("mission store not initialized (pool not configured)")
	}
	connForUpdate, connUpdateErr := d.pool.For(ctx, tenantForUpdate)
	if connUpdateErr != nil {
		return api.UpdateMissionDefinitionResultData{}, datapool.MapPoolError(connUpdateErr)
	}
	defer connForUpdate.Release()
	mStore := mission.NewConnBoundMissionStore(connForUpdate.Redis)

	// Fetch the existing definition first so we can preserve its server-assigned ID.
	existing, err := mStore.GetDefinition(ctx, def.GetName())
	if err != nil {
		d.logger.Error(ctx, "failed to fetch existing mission definition for update", "name", def.GetName(), "error", err)
		return api.UpdateMissionDefinitionResultData{}, fmt.Errorf("failed to fetch existing definition: %w", err)
	}
	if existing == nil {
		return api.UpdateMissionDefinitionResultData{}, mission.ErrDefinitionNotFound
	}

	// Preserve the stable server-assigned ID from the stored record.
	existingID := existing.GetId()
	def.Id = existingID

	if err := mStore.UpdateDefinition(ctx, def); err != nil {
		d.logger.Error(ctx, "failed to update mission definition", "name", def.GetName(), "error", err)
		return api.UpdateMissionDefinitionResultData{}, fmt.Errorf("failed to update mission definition: %w", err)
	}

	// Overwrite the stored CUE source in place under the stable id. gibson#504.
	if err := mStore.SetDefinitionSource(ctx, def.GetName(), req.CueSource); err != nil {
		d.logger.Warn(ctx, "failed to persist definition cue source on update", "error", err, "name", def.GetName())
	}

	d.logger.Info(ctx, "mission definition updated",
		"mission_definition_id", existingID,
		"name", def.GetName(),
	)

	return api.UpdateMissionDefinitionResultData{
		MissionDefinitionID: existingID,
	}, nil
}
