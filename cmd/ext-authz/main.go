// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command ext-authz is the Gibson external authorization sidecar.
//
// It serves the Envoy External Authorization gRPC service
// (envoy.service.auth.v3.Authorization/Check) and a small HTTPS
// listener for /healthz.
//
// Per the unified-identity-and-authorization spec:
//
//   - JWT validation is Envoy's job (jwt_authn filter against Zitadel
//     JWKS). ext-authz consumes the verified JWT claims that Envoy
//     forwards via x-jwt-payload.
//   - ext-authz consults OpenFGA via a cached Checker (TTL + tuple-
//     write invalidation hooks).
//   - When the request carries a capability-grant JWT (X-Capability-Grant
//     header) ALONGSIDE an identity, ext-authz verifies it against the
//     daemon's published JWKS and treats it as a constraint: it must be
//     bound to the caller and cover the method, and FGA still decides.
//   - When a daemon-minted task grant is the SOLE credential — a dispatched
//     component holds nothing else (ADR-0016) — the verified grant is the
//     authorization, and the requested method must be in its allowed_rpcs
//     (gibson#1605).
//   - On allow, ext-authz emits the canonical x-gibson-identity-*
//     header set on the upstream request. Headers are NOT HMAC-signed —
//     the channel between Envoy and the daemon is SPIFFE-pinned mTLS.
//
// Per security-hardening Spec 3 R13, R16:
//
//   - The Envoy ↔ ext-authz gRPC channel is SPIFFE-pinned mTLS. The
//     Envoy SVID allowlist is fixed at startup (EXT_AUTHZ_ENVOY_SVID).
//     There is no plain-TCP fallback. Missing/unreadable SVIDs at
//     startup cause a non-zero exit after a 30s grace period.
//   - The HTTP health/metrics surface is HTTPS-only with mandatory
//     mTLS for Prometheus scrape, served from cert-manager-issued
//     material under /etc/extauthz/tls/health/{tls.crt,tls.key,ca.crt}.
//
// Configuration (env vars):
//
//	EXT_AUTHZ_GRPC_ADDR             default :9001
//	EXT_AUTHZ_HTTP_ADDR             default :9002
//	EXT_AUTHZ_REGISTRY_PATH         default /etc/gibson/registry.yaml
//	                                (mounted from a ConfigMap rendered
//	                                from the SDK release artifact)
//	EXT_AUTHZ_FGA_ADDR              REQUIRED — missing causes immediate exit(1)
//	                                (zero-trust-hardening Req 11.1)
//	EXT_AUTHZ_FGA_STORE_ID          required in production
//	EXT_AUTHZ_FGA_CACHE_TTL         default 30s
//	EXT_AUTHZ_FGA_CACHE_MAX_SIZE    default 100000
//	EXT_AUTHZ_CGJWT_KEYS_URL        required in production — the daemon per-kid
//	                                key endpoint base; backs BOTH the dispatch
//	                                CG-JWT verifier and the component verifier
//	                                (one key-resolution path, ADR-0045).
//	                                MUST be https — it is fetched over SPIFFE
//	                                mTLS pinned to EXT_AUTHZ_DAEMON_SVID, like
//	                                the authz-registry fetch. A plaintext URL
//	                                is a startup error.
//	EXT_AUTHZ_DAEMON_SVID           REQUIRED whenever EXT_AUTHZ_CGJWT_KEYS_URL or
//	                                EXT_AUTHZ_REGISTRY_URL is set — the daemon
//	                                SPIFFE ID both fetches pin their peer to
//	                                (e.g. spiffe://zeroroot.ai/platform/daemon)
//	EXT_AUTHZ_CGJWT_ISSUER          required (daemon CG authority URL)
//	EXT_AUTHZ_CGJWT_AUDIENCE        default gibson-daemon
//	EXT_AUTHZ_CGJWT_TTL             default 1h
//	EXT_AUTHZ_CGJWT_KEYS_URL        per-kid component key descriptor base; unset
//	                                disables component CG-JWT auth entirely
//	                                (component token `aud` is pinned in code to
//	                                the stable constant zeroroot.ai/gibson-daemon,
//	                                not configured — gibson#1246; the former
//	                                EXT_AUTHZ_CGJWT_COMPONENT_AUDIENCE is retired)
//	EXT_AUTHZ_CGJWT_DESCRIPTOR_TTL  default 5m
//	EXT_AUTHZ_CGJWT_REPLAY_CACHE_MAX_ENTRIES
//	                                default 100000 — per-pod (kid, jti) single-use
//	                                cache for component tokens (gibson#1246)
//	EXT_AUTHZ_GRPC_REFLECTION       default off; set to "1" to enable gRPC reflection
//	                                (zero-trust-hardening Req 11.2; leave unset in prod)
//	EXT_AUTHZ_ZITADEL_ISSUER        REQUIRED — Zitadel issuer allowlist (URL or
//	                                comma-separated list); the JWT iss claim must match.
//	SPIFFE_ENDPOINT_SOCKET          REQUIRED — SPIRE Workload API socket path
//	                                (e.g. unix:///run/spire/agent-sockets/spire-agent.sock)
//	EXT_AUTHZ_ENVOY_SVID            REQUIRED — Envoy peer SVID to authorize
//	                                (e.g. spiffe://zeroroot.ai/ns/gibson/sa/gibson-envoy);
//	                                comma-separated list also accepted.
//	EXT_AUTHZ_HEALTH_CERT_DIR       default /etc/extauthz/tls/health — directory
//	                                holding tls.crt, tls.key, ca.crt for the HTTPS
//	                                health/metrics listener.
//
// Spec: unified-identity-and-authorization Phase 2; security-hardening R13/R16.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zeroroot-ai/gibson/internal/infra/authz"
	"github.com/zeroroot-ai/gibson/internal/infra/otelinit"
	"github.com/zeroroot-ai/gibson/internal/infra/readiness"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/server"
	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// spiffeStartupGrace is the maximum time we wait at startup for SPIRE to
// hand us a valid SVID before exiting non-zero. There is no fallback.
const spiffeStartupGrace = 30 * time.Second

func main() {
	level := slog.LevelInfo
	if v := os.Getenv("EXT_AUTHZ_LOG_LEVEL"); v == "debug" || v == "DEBUG" {
		level = slog.LevelDebug
	}

	// otelinit.Init wires OTel traces + metrics + a structured
	// slog.Logger. Endpoint resolves via OTEL_EXPORTER_OTLP_ENDPOINT;
	// when unset the providers are no-op so unit tests / loopback runs
	// don't require a collector. Each call returns an independent instance
	// (no global state mutation; call SetGlobal to opt into global providers).
	obsProvider, obsErr := otelinit.Init(context.Background(), "ext-authz",
		otelinit.WithLogLevel(level),
	)
	var log *slog.Logger
	if obsErr != nil {
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
		log.Warn("otelinit.Init failed; falling back to local slog", "err", obsErr)
	} else {
		log = obsProvider.Logger
		// Set global OTel providers so auto-instrumented libraries (including
		// the ext-authz FGA OTel histogram in internal/fga/platform_client.go
		// which calls otel.GetMeterProvider()) pick up this instance's providers.
		obsProvider.SetGlobal()
	}

	grpcAddr := envOr("EXT_AUTHZ_GRPC_ADDR", ":9001")
	httpAddr := envOr("EXT_AUTHZ_HTTP_ADDR", ":9002")

	// Identity-bearing context + SPIFFE source must come first: the FGA
	// registry is fetched from the daemon over mTLS (deploy#852), which needs
	// the X.509 source.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// SPIFFE Workload API source (mandatory; security-hardening R13).
	x509Source, err := loadSPIFFESource(ctx, log)
	if err != nil {
		log.Error("init SPIFFE workload api", "err", err)
		os.Exit(1)
	}
	defer func() {
		if cerr := x509Source.Close(); cerr != nil {
			log.Warn("close SPIFFE x509 source", "err", cerr)
		}
	}()

	// Load the FGA registry. Preferred path (deploy#852): fetch it from the
	// daemon's mTLS authz-registry endpoint so ext-authz always enforces the
	// SAME policy the running daemon compiled in — there is no separately-
	// versioned OCI artifact to drift behind the deployed daemon (which used to
	// silently default-deny newly-added RPCs like SetSignupProgress). Falls
	// back to the file path (EXT_AUTHZ_REGISTRY_PATH) when EXT_AUTHZ_REGISTRY_URL
	// is unset (tests / air-gapped installs).
	registryBytes, registrySrc, err := loadRegistryBytes(ctx, log, x509Source)
	if err != nil {
		log.Error("load FGA RPC registry", "err", err)
		os.Exit(1)
	}
	reg, err := fga.LoadRegistry(registryBytes)
	if err != nil {
		log.Error("parse FGA RPC registry", "err", err)
		os.Exit(1)
	}
	log.Info("FGA registry loaded", "entries", reg.Len(), "source", registrySrc)

	// FGA client + cached checker. The platform-clients FGAClient
	// applies a per-call timeout floor under the Envoy ext_authz
	// budget (audit fix).
	checker, fgaClient := buildChecker(log, reg)
	cacheTTL := durationOr("EXT_AUTHZ_FGA_CACHE_TTL", 30*time.Second)
	cacheMax := intOr("EXT_AUTHZ_FGA_CACHE_MAX_SIZE", 100_000)
	cachedChecker := fga.NewCachedChecker(checker, cacheTTL, cacheMax)

	// Both capability-grant verifiers, on one SVID-pinned key transport.
	cgVerifier, componentVerifier, err := buildCGVerifiers(log, x509Source, x509Source)
	if err != nil {
		log.Error("init capability-grant verifiers", "err", err)
		os.Exit(1)
	}

	// Issuer allowlist for the JWT iss check (security-hardening R13).
	issuerAllowlist, err := loadIssuerAllowlist()
	if err != nil {
		log.Error("init issuer allowlist", "err", err)
		os.Exit(1)
	}
	log.Info("issuer allowlist loaded", "issuers", issuerAllowlist)

	// Build the gRPC SPIFFE-mTLS server credentials. The peer authorizer
	// pins to the configured Envoy SVID(s); any other SVID is rejected.
	envoyAuthorizer, err := buildEnvoyAuthorizer()
	if err != nil {
		log.Error("init envoy SVID allowlist", "err", err)
		os.Exit(1)
	}
	grpcTLSCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, envoyAuthorizer)

	// Panic-recovery interceptor MUST be the outermost UnaryInterceptor
	// so panics raised by inner interceptors are also caught. Audit fix:
	// before this, a single panic in the FGA response handler would tear
	// down the gRPC connection and Envoy would serve 5xx for every other
	// in-flight request on that connection.
	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(grpcTLSCfg)),
		grpc.UnaryInterceptor(server.UnaryPanicRecovery(log)),
	)
	authv3.RegisterAuthorizationServer(grpcSrv, server.NewEnvoyAuthzServer(server.Config{
		Cache:           cachedChecker,
		CGJWT:           cgVerifier,
		Component:       componentVerifier,
		Logger:          log,
		IssuerAllowlist: issuerAllowlist,
	}))
	// gRPC reflection is disabled by default in production.
	// Set EXT_AUTHZ_GRPC_REFLECTION=1 to enable (dev/debug only).
	// Req 11.2: production deployments must leave this unset.
	if os.Getenv("EXT_AUTHZ_GRPC_REFLECTION") == "1" {
		reflection.Register(grpcSrv)
		log.Info("gRPC reflection enabled (EXT_AUTHZ_GRPC_REFLECTION=1)")
	}

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Error("bind gRPC listener", "addr", grpcAddr, "err", err)
		os.Exit(1)
	}

	// HTTPS server (healthz + readyz). TLS material is mounted from the
	// cert-manager-issued Secret. Prometheus scrape requires a client cert
	// chained to the platform CA bundle; the chart-side allowlist of peer
	// SVIDs is enforced via VerifyPeerCertificate below.
	//
	// /healthz — process liveness only (LivenessHandler).
	// /readyz  — dependency reachability (runs every registered probe).
	//           The FGA probe issues a Check against a synthetic canary
	//           tuple; transport errors flip the pod to 503 and kubelet
	//           pulls it from service-endpoints. Audit fix: before this,
	//           /healthz was the only probe and a wedged FGA left the pod
	//           "Ready" forever, returning codes.Unavailable to every
	//           dashboard request.
	readyAgg := readiness.NewAggregator()
	readyAgg.Register(fga.NewReadinessProbe(fgaClient, "fga"))
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", readyAgg.LivenessHandler())
	mux.Handle("GET /readyz", readyAgg.ReadyHandler())
	healthCertDir := envOr("EXT_AUTHZ_HEALTH_CERT_DIR", "/etc/extauthz/tls/health")
	healthTLSCfg, err := buildHealthTLSConfig(log, healthCertDir)
	if err != nil {
		log.Error("init health TLS", "dir", healthCertDir, "err", err)
		os.Exit(1)
	}
	httpSrv := &http.Server{
		Addr:      httpAddr,
		Handler:   mux,
		TLSConfig: healthTLSCfg,
	}

	grpcErrC := make(chan error, 1)
	go func() {
		log.Info("gRPC server starting (SPIFFE mTLS)", "addr", grpcAddr)
		if err := grpcSrv.Serve(grpcLis); err != nil {
			grpcErrC <- fmt.Errorf("gRPC server: %w", err)
		}
	}()
	httpErrC := make(chan error, 1)
	go func() {
		log.Info("HTTPS health server starting", "addr", httpAddr, "cert_dir", healthCertDir)
		// Cert and key paths are sourced from TLSConfig.GetCertificate via
		// the cert-manager-issued material; pass empty paths to ListenAndServeTLS.
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErrC <- fmt.Errorf("HTTPS server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, draining")
	case err := <-grpcErrC:
		log.Error("fatal gRPC error", "err", err)
		os.Exit(1)
	case err := <-httpErrC:
		log.Error("fatal HTTPS error", "err", err)
		os.Exit(1)
	}

	grpcSrv.GracefulStop()
	if err := httpSrv.Shutdown(context.Background()); err != nil {
		log.Error("HTTPS shutdown error", "err", err)
	}
	// Flush buffered OTel telemetry. 5s ceiling so a stuck collector
	// can't keep the process alive after a SIGTERM.
	if obsProvider != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := obsProvider.Shutdown(shutCtx); err != nil {
			log.Warn("observability shutdown error", "err", err)
		}
		shutCancel()
	}
	log.Info("ext-authz stopped cleanly")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func durationOr(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func intOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// buildChecker constructs the FGA Checker over a platform-clients
// FGAClient. The PerCallTimeout floor here is THE fix for the audit
// finding "no per-call FGA timeout floor (so slow OpenFGA consumes
// Envoy's full 5s ext_authz budget)" — 1500ms sits comfortably under
// the Envoy ext_authz default budget while leaving headroom for
// derivation, header emission, and the daemon-side HMAC validation.
//
// Returns the Checker plus the underlying fga.FGAClient so the
// readiness probe can share the same dialled client.
func buildChecker(log *slog.Logger, reg *fga.Registry) (*fga.Checker, fga.FGAClient) {
	fgaAddr := os.Getenv("EXT_AUTHZ_FGA_ADDR")
	if fgaAddr == "" {
		// Fail fast: a missing FGA address means every authenticated RPC
		// would silently deny all callers. This is a mis-configured start,
		// not a graceful degradation. Req 11.1 — refuse to start.
		log.Error("EXT_AUTHZ_FGA_ADDR is required — refusing to start without FGA endpoint (zero-trust-hardening Req 11.1)")
		os.Exit(1)
	}
	storeID := os.Getenv("EXT_AUTHZ_FGA_STORE_ID")
	if storeID == "" {
		log.Error("EXT_AUTHZ_FGA_STORE_ID required when EXT_AUTHZ_FGA_ADDR is set")
		os.Exit(1)
	}
	modelID := os.Getenv("EXT_AUTHZ_FGA_MODEL_ID")
	if modelID == "" {
		log.Error("EXT_AUTHZ_FGA_MODEL_ID required (platform-clients FGAClient requires an authorization model ID)")
		os.Exit(1)
	}

	perCallTimeout := durationOr("EXT_AUTHZ_FGA_PER_CALL_TIMEOUT", 1500*time.Millisecond)

	client, err := fga.NewPlatformFGAClient(authz.FGAClientOptions{
		Endpoint:       fgaAddr,
		StoreID:        storeID,
		ModelID:        modelID,
		PerCallTimeout: perCallTimeout,
		Logger:         log,
	})
	if err != nil {
		log.Error("create platform-clients FGA client", "addr", fgaAddr, "err", err)
		os.Exit(1)
	}

	// Startup self-check (ext-authz#24). The platform-clients constructor
	// does NOT dial; an explicit round-trip catches port/protocol
	// mismatches the way deploy#140 did. Fail-fast on transport-class
	// errors so kubelet's CrashLoopBackoff + container log surface the
	// misconfiguration immediately instead of having the dashboard 500
	// silently for hours.
	if err := fga.SelfCheck(context.Background(), client, fgaAddr); err != nil {
		log.Error("FGA startup self-check failed — refusing to start",
			"addr", fgaAddr, "err", err)
		os.Exit(1)
	}
	log.Info("OpenFGA client (platform-clients/authz) connected and self-check passed",
		"addr", fgaAddr, "store_id", storeID, "model_id", modelID,
		"per_call_timeout", perCallTimeout.String())
	return fga.NewChecker(client, reg), client
}

// buildCGVerifiers wires both capability-grant verifiers onto ONE transport to
// the daemon's per-kid key endpoint.
//
// They are built together rather than side by side in main because "both
// verifiers resolve keys through the same SVID-pinned client" is the property
// that matters, not an ordering main happens to get right: the dispatch
// verifier resolves the daemon's own signing key from that endpoint and the
// component verifier resolves the descriptor binding a component kid to an FGA
// principal, so an unauthenticated origin compromises either one on its own.
//
// Both returned verifiers are nil when EXT_AUTHZ_CGJWT_KEYS_URL is unset, which
// disables the capability-grant paths entirely.
func buildCGVerifiers(
	log *slog.Logger,
	svid x509svid.Source,
	bundle x509bundle.Source,
) (*cgjwt.Verifier, *cgjwt.ComponentVerifier, error) {
	keysClient, err := buildCGKeysClient(log, svid, bundle)
	if err != nil {
		return nil, nil, err
	}
	dispatch, err := buildCGVerifier(log, keysClient)
	if err != nil {
		return nil, nil, fmt.Errorf("dispatch capability-grant verifier: %w", err)
	}
	component, err := buildComponentVerifier(log, keysClient)
	if err != nil {
		return nil, nil, fmt.Errorf("component capability-grant verifier: %w", err)
	}
	return dispatch, component, nil
}

// buildCGKeysClient builds the HTTP client both CG-JWT verifiers use to fetch
// per-kid key documents from the daemon (EXT_AUTHZ_CGJWT_KEYS_URL). It returns
// (nil, nil) when the keys URL is unset — both verifiers are then disabled and
// there is nothing to fetch.
//
// The transport is SPIFFE mTLS pinned to EXT_AUTHZ_DAEMON_SVID, identical to
// the authz-registry fetch in loadRegistryBytes, and for the identical reason:
// the fetched document is not merely data the daemon happens to hold, it is
// the assertion ext-authz turns into an identity. An unauthenticated origin for
// it is an unauthenticated origin for every caller's identity
// (GHSA-8m76-9r77-xvh3).
//
// A non-https keys URL is a startup error, not a downgrade. Go's http.Transport
// applies TLSClientConfig only to https:// URLs, so a plaintext URL paired with
// this client would silently fetch in the clear — the one outcome this function
// exists to prevent. There is deliberately no scheme-conditional path and no
// opt-out flag: per ADR-0027 the cutover is wholesale, and a transitional
// plaintext branch is precisely the parallel codepath that would outlive the
// transition. The chart must render an https :8086 URL (deploy#1187).
func buildCGKeysClient(log *slog.Logger, svid x509svid.Source, bundle x509bundle.Source) (*http.Client, error) {
	keysURL := strings.TrimSpace(os.Getenv("EXT_AUTHZ_CGJWT_KEYS_URL"))
	if keysURL == "" {
		return nil, nil
	}
	parsed, err := url.Parse(keysURL)
	if err != nil {
		return nil, fmt.Errorf("EXT_AUTHZ_CGJWT_KEYS_URL %q is not a parseable URL: %w", keysURL, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf(
			"EXT_AUTHZ_CGJWT_KEYS_URL must be https, got scheme %q (%s): the per-kid key document "+
				"is the trust anchor for every capability-grant token, so it is fetched over SPIFFE "+
				"mTLS pinned to EXT_AUTHZ_DAEMON_SVID — point this at the daemon's mTLS listener "+
				"(https://<daemon>:8086/capabilitygrant/v1/keys), not the plaintext bootstrap listener",
			parsed.Scheme, keysURL)
	}
	client, err := daemonMTLSClient(svid, bundle, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("capability-grant key transport: %w", err)
	}
	log.Info("capability-grant key transport is SVID-pinned mTLS",
		"keys_url", keysURL, "daemon_svid", os.Getenv("EXT_AUTHZ_DAEMON_SVID"))
	return client, nil
}

// daemonMTLSClient returns an HTTP client whose peer is pinned to the daemon
// SPIFFE ID in EXT_AUTHZ_DAEMON_SVID. Both daemon-ward fetches — the authz
// registry and the per-kid CG key documents — use it, so there is one
// authorizer idiom and one env var for "which daemon do we trust".
func daemonMTLSClient(svid x509svid.Source, bundle x509bundle.Source, timeout time.Duration) (*http.Client, error) {
	raw := strings.TrimSpace(os.Getenv("EXT_AUTHZ_DAEMON_SVID"))
	if raw == "" {
		return nil, errors.New(
			"EXT_AUTHZ_DAEMON_SVID required (e.g. spiffe://zeroroot.ai/platform/daemon) — " +
				"a daemon-ward fetch MUST be SVID-pinned")
	}
	daemonID, err := spiffeid.FromString(raw)
	if err != nil {
		return nil, fmt.Errorf("EXT_AUTHZ_DAEMON_SVID %q is not a parseable SPIFFE ID: %w", raw, err)
	}
	// AuthorizeID, not AuthorizeMemberOf: a valid SVID from our own trust
	// domain is not the daemon. Any other workload in zeroroot.ai holds one.
	tlsCfg := tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeID(daemonID))
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   timeout,
	}, nil
}

// buildCGVerifier wires the verifier for daemon-minted dispatch CG-JWTs. It
// resolves the daemon signing key per-kid from EXT_AUTHZ_CGJWT_KEYS_URL — the
// same endpoint the component verifier uses, because ADR-0045 collapses key
// resolution to one fetch-by-kid path. There is no JWKS-wide document.
//
// keysClient is the SVID-pinned transport from buildCGKeysClient; it is nil
// exactly when the keys URL is unset, which is the same condition that
// disables this verifier.
func buildCGVerifier(log *slog.Logger, keysClient *http.Client) (*cgjwt.Verifier, error) {
	keysURL := os.Getenv("EXT_AUTHZ_CGJWT_KEYS_URL")
	if keysURL == "" {
		log.Warn("EXT_AUTHZ_CGJWT_KEYS_URL not set — capability-grant short-circuit disabled")
		// Return a no-op verifier; the server treats nil as "no
		// short-circuit possible" and falls through to FGA.
		return nil, nil
	}
	issuer := os.Getenv("EXT_AUTHZ_CGJWT_ISSUER")
	if issuer == "" {
		return nil, errors.New("EXT_AUTHZ_CGJWT_ISSUER required when the CG keys URL is set")
	}
	audience := envOr("EXT_AUTHZ_CGJWT_AUDIENCE", "gibson-daemon")
	ttl := durationOr("EXT_AUTHZ_CGJWT_TTL", time.Hour)
	return cgjwt.NewVerifier(cgjwt.Config{
		KeysBaseURL:      keysURL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		TTL:              ttl,
		HTTPClient:       keysClient,
	})
}

// buildComponentVerifier wires the verifier for components' self-signed per-RPC
// CG-JWTs (ADR-0045). EXT_AUTHZ_CGJWT_KEYS_URL is the daemon per-kid key
// endpoint base on the daemon's SPIFFE-mTLS listener, e.g.
// "https://gibson:8086/capabilitygrant/v1/keys". When unset, the component
// path is disabled (a component token alone is unauthenticated).
//
// keysClient is the SVID-pinned transport from buildCGKeysClient. The
// descriptor it fetches is what binds a component kid to an FGA principal, so
// the peer that serves it is pinned to the daemon's SVID
// (GHSA-8m76-9r77-xvh3).
//
// The component token audience is pinned to the fixed protocol constant both
// SDKs mint — capabilitygrant.AudienceGibsonDaemon ("zeroroot.ai/gibson-daemon")
// — NOT read from the environment (gibson#1246). It is no longer a
// deployment-specific value now that request binding lives in the token's
// `method` claim, so there is nothing for an operator to configure. Making it
// configurable would only invite drift between the pin and what the SDKs sign,
// which is an all-component-auth outage. (The former
// EXT_AUTHZ_CGJWT_COMPONENT_AUDIENCE env var is retired; any lingering Helm
// value for it is now ignored.)
func buildComponentVerifier(log *slog.Logger, keysClient *http.Client) (*cgjwt.ComponentVerifier, error) {
	keysURL := os.Getenv("EXT_AUTHZ_CGJWT_KEYS_URL")
	if keysURL == "" {
		log.Warn("EXT_AUTHZ_CGJWT_KEYS_URL not set — component CG-JWT auth disabled")
		return nil, nil
	}
	audiences := []string{capabilitygrant.AudienceGibsonDaemon}
	ttl := durationOr("EXT_AUTHZ_CGJWT_DESCRIPTOR_TTL", 5*time.Minute)
	replayMax := intOr("EXT_AUTHZ_CGJWT_REPLAY_CACHE_MAX_ENTRIES", cgjwt.DefaultReplayCacheMaxEntries)
	log.Info("component CG-JWT auth enabled",
		"keys_url", keysURL,
		"expected_audiences", audiences,
		"descriptor_ttl", ttl.String(),
		"replay_cache_max_entries", replayMax)
	return cgjwt.NewComponentVerifier(cgjwt.ComponentConfig{
		KeysBaseURL:           keysURL,
		TTL:                   ttl,
		ExpectedAudiences:     audiences,
		ReplayCacheMaxEntries: replayMax,
		HTTPClient:            keysClient,
	})
}

// loadIssuerAllowlist parses EXT_AUTHZ_ZITADEL_ISSUER as either a single
// issuer URL or a comma-separated list. Whitespace and empty entries are
// ignored; an empty allowlist returns an error so misconfiguration cannot
// silently allow anything.
//
// Spec: security-hardening R13.
func loadIssuerAllowlist() ([]string, error) {
	raw := os.Getenv("EXT_AUTHZ_ZITADEL_ISSUER")
	if raw == "" {
		return nil, errors.New("EXT_AUTHZ_ZITADEL_ISSUER required (single issuer URL or comma-separated list)")
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("EXT_AUTHZ_ZITADEL_ISSUER produced an empty allowlist after trimming")
	}
	return out, nil
}

// loadRegistryBytes returns the FGA authz-registry bytes plus a short label
// describing where they came from (for the startup log).
//
// Preferred path (deploy#852): when EXT_AUTHZ_REGISTRY_URL is set, fetch the
// registry from the daemon's mTLS authz-registry endpoint, pinning the daemon's
// SVID (EXT_AUTHZ_DAEMON_SVID) so a poisoned/impersonated source can never feed
// ext-authz a forged policy. The daemon is the single source of truth, so the
// enforced policy can never drift behind the deployed daemon. The fetch retries
// (the daemon usually comes up after ext-authz) for up to
// EXT_AUTHZ_REGISTRY_FETCH_TIMEOUT (default 300s); on timeout ext-authz exits
// (crash-loops) rather than enforce nothing — k8s restarts it once the daemon
// is reachable.
//
// Fallback: when EXT_AUTHZ_REGISTRY_URL is unset, read EXT_AUTHZ_REGISTRY_PATH
// (default /etc/gibson/registry.yaml). This keeps tests and air-gapped installs
// (chart embeddedRegistry) working with no daemon dependency.
func loadRegistryBytes(ctx context.Context, log *slog.Logger, x509Source *workloadapi.X509Source) ([]byte, string, error) {
	url := strings.TrimSpace(os.Getenv("EXT_AUTHZ_REGISTRY_URL"))
	if url == "" {
		path := envOr("EXT_AUTHZ_REGISTRY_PATH", "/etc/gibson/registry.yaml")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("read registry file %q: %w", path, err)
		}
		return b, "file:" + path, nil
	}

	// mTLS client pinned to the daemon's SVID. This is the integrity guarantee:
	// ext-authz verifies it is talking to the real daemon before trusting any
	// byte of the policy it will enforce. Same helper — and so the same pin —
	// as the per-kid CG key fetch.
	client, err := daemonMTLSClient(x509Source, x509Source, 15*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("authz-registry transport (EXT_AUTHZ_REGISTRY_URL is set): %w", err)
	}

	total := durationOr("EXT_AUTHZ_REGISTRY_FETCH_TIMEOUT", 300*time.Second)
	deadline := time.Now().Add(total)
	backoff := 2 * time.Second
	const maxBackoff = 15 * time.Second
	var lastErr error
	for attempt := 1; ; attempt++ {
		b, err := fetchRegistryOnce(ctx, client, url)
		if err == nil {
			return b, "daemon-mtls:" + url, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			break
		}
		log.Warn("authz-registry fetch failed; retrying (daemon may still be starting)",
			"attempt", attempt, "url", url, "err", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("authz-registry fetch cancelled: %w", ctx.Err())
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	return nil, "", fmt.Errorf("authz-registry fetch from %s timed out after %s: %w", url, total, lastErr)
}

// fetchRegistryOnce performs a single GET of the registry endpoint.
func fetchRegistryOnce(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("empty registry body")
	}
	return b, nil
}

// loadSPIFFESource opens the SPIRE Workload API socket and waits up to
// spiffeStartupGrace for the first SVID to arrive. There is no fallback;
// if SPIRE is unreachable, ext-authz must not start.
//
// Spec: security-hardening R13.
func loadSPIFFESource(ctx context.Context, log *slog.Logger) (*workloadapi.X509Source, error) {
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		return nil, errors.New("SPIFFE_ENDPOINT_SOCKET required (e.g. unix:///run/spire/agent-sockets/spire-agent.sock)")
	}

	graceCtx, cancel := context.WithTimeout(ctx, spiffeStartupGrace)
	defer cancel()

	src, err := workloadapi.NewX509Source(graceCtx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(socket),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("workload API NewX509Source (socket=%s): %w", socket, err)
	}
	svid, err := src.GetX509SVID()
	if err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("no SVID after %s grace period (socket=%s): %w", spiffeStartupGrace, socket, err)
	}
	log.Info("SPIFFE workload API ready", "spiffe_id", svid.ID.String(), "socket", socket)
	return src, nil
}

// buildEnvoyAuthorizer parses EXT_AUTHZ_ENVOY_SVID into a tlsconfig.Authorizer
// that pins the gRPC peer to the configured Envoy SVID(s).
//
// Spec: security-hardening R13 — peer SVID is fixed at startup.
func buildEnvoyAuthorizer() (tlsconfig.Authorizer, error) {
	raw := os.Getenv("EXT_AUTHZ_ENVOY_SVID")
	if raw == "" {
		return nil, errors.New("EXT_AUTHZ_ENVOY_SVID required (e.g. spiffe://zeroroot.ai/ns/gibson/sa/gibson-envoy)")
	}
	parts := strings.Split(raw, ",")
	ids := make([]spiffeid.ID, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := spiffeid.FromString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", p, err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("EXT_AUTHZ_ENVOY_SVID produced an empty allowlist after trimming")
	}
	if len(ids) == 1 {
		return tlsconfig.AuthorizeID(ids[0]), nil
	}
	return tlsconfig.AuthorizeOneOf(ids...), nil
}

// buildHealthTLSConfig loads the cert-manager-issued cert/key/ca for the
// HTTPS health/metrics listener. Client mTLS is mandatory: the peer must
// present a cert chained to the mounted CA bundle (the chart's
// gibson-platform-ca). Per-SVID allowlisting (e.g. only Prometheus's SVID)
// is layered on top via VerifyPeerCertificate.
//
// Spec: security-hardening R16.
func buildHealthTLSConfig(log *slog.Logger, dir string) (*tls.Config, error) {
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	caPath := filepath.Join(dir, "ca.crt")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load health server cert (%s, %s): %w", certPath, keyPath, err)
	}
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read health CA (%s): %w", caPath, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("parse health CA PEM (%s): no certs", caPath)
	}

	// Optional per-SVID allowlist for the HTTPS surface (Prometheus etc).
	// EXT_AUTHZ_HEALTH_PEER_SVIDS is a comma-separated list of SPIFFE IDs.
	// When set, only peers whose URI SAN matches one of these IDs are
	// accepted (in addition to passing chain verification against caPool).
	peerSVIDs, err := parseHealthPeerSVIDs()
	if err != nil {
		return nil, err
	}
	if len(peerSVIDs) > 0 {
		log.Info("health peer SVID allowlist configured", "ids", peerSVIDs)
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}

	if len(peerSVIDs) > 0 {
		allow := make(map[string]struct{}, len(peerSVIDs))
		for _, id := range peerSVIDs {
			allow[id] = struct{}{}
		}
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("health TLS: no client cert presented")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("health TLS: parse client cert: %w", err)
			}
			for _, u := range leaf.URIs {
				if _, ok := allow[u.String()]; ok {
					return nil
				}
			}
			return fmt.Errorf("health TLS: client SVID not in allowlist")
		}
	}

	return cfg, nil
}

func parseHealthPeerSVIDs() ([]string, error) {
	raw := os.Getenv("EXT_AUTHZ_HEALTH_PEER_SVIDS")
	if raw == "" {
		// No per-SVID allowlist configured; chain verification against the
		// platform CA is enforced unconditionally above.
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := spiffeid.FromString(p); err != nil {
			return nil, fmt.Errorf("EXT_AUTHZ_HEALTH_PEER_SVIDS: invalid SPIFFE ID %q: %w", p, err)
		}
		out = append(out, p)
	}
	return out, nil
}
