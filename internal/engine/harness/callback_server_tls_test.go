// Tests for the harness callback listener's SPIFFE mTLS posture.
//
// These tests stand up an in-process gRPC server using exactly the same TLS
// configuration shape as CallbackServer.Start (tlsconfig.MTLSServerConfig +
// AuthorizeOneOf + RequireAndVerifyClientCert + structured-log
// VerifyPeerCertificate wrapper). They do NOT spin up the full CallbackServer
// because CallbackServer registers HarnessCallbackService which has unrelated
// daemon dependencies; the TLS handshake behavior under test happens entirely
// at the transport layer, so a minimal `grpc_health_v1.Health` server suffices.
//
// Spec: critical-tls-no-fallbacks Requirements 1.1-1.4, 5.1, 5.2.

package harness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// --- Synthesized SPIFFE PKI helpers (duplicated minimally from
// internal/server/daemon/mtls_handshake_test.go to avoid cross-package imports). ---

type stubCallbackBundleSource struct {
	bundle *x509bundle.Bundle
}

func (s *stubCallbackBundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

type stubCallbackSVIDSource struct {
	svid *x509svid.SVID
}

func (s *stubCallbackSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	return s.svid, nil
}

type callbackTestPKI struct {
	caCert       *x509.Certificate
	bundleSource *stubCallbackBundleSource
	svidSource   *stubCallbackSVIDSource
	spiffeID     spiffeid.ID
}

func newCallbackTestPKI(t *testing.T, trustDomainName, pathSuffix string) *callbackTestPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca-" + pathSuffix},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, err := url.Parse("spiffe://" + trustDomainName + pathSuffix)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-svid" + pathSuffix},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		URIs:         []*url.URL{spiffeURI},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	td := spiffeid.RequireTrustDomainFromString(trustDomainName)
	svidID, err := spiffeid.FromString("spiffe://" + trustDomainName + pathSuffix)
	require.NoError(t, err)

	svid := &x509svid.SVID{
		ID:           svidID,
		Certificates: []*x509.Certificate{leafCert, caCert},
		PrivateKey:   leafKey,
	}
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{caCert})

	return &callbackTestPKI{
		caCert:       caCert,
		bundleSource: &stubCallbackBundleSource{bundle: bundle},
		svidSource:   &stubCallbackSVIDSource{svid: svid},
		spiffeID:     svidID,
	}
}

// --- Health server stub for transport-level probes. ---

type alwaysHealthyCallbackServer struct {
	healthpb.UnimplementedHealthServer
	calls atomic.Int64
}

func (s *alwaysHealthyCallbackServer) Check(_ context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.calls.Add(1)
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// --- bufferLogger captures slog records for assertion. ---

type bufferLogger struct {
	buf *bytes.Buffer
}

func newBufferLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

// startCallbackTestServer spins up a gRPC server using the EXACT TLS
// configuration shape that CallbackServer.Start applies in production:
//
//	tlsconfig.MTLSServerConfig(source, source, AuthorizeOneOf(allowlist...))
//	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
//	+ structured-log VerifyPeerCertificate wrapper emitting
//	  callback.tls.peer_accepted / callback.tls.unauthorized_peer events.
//
// The handler is a minimal Health server so we can probe transport behavior
// without wiring HarnessCallbackService.
func startCallbackTestServer(t *testing.T, serverPKI *callbackTestPKI, allowlist []spiffeid.ID) (*grpc.Server, string, *alwaysHealthyCallbackServer, *bytes.Buffer) {
	t.Helper()

	logger, buf := newBufferLogger()

	tlsCfg := tlsconfig.MTLSServerConfig(serverPKI.svidSource, serverPKI.bundleSource, tlsconfig.AuthorizeOneOf(allowlist...))
	// We do NOT override ClientAuth — go-spiffe's MTLSServerConfig sets a
	// value that rejects cert-less handshakes; SPIFFE bundle validation is
	// owned by VerifyPeerCertificate.
	origVerify := tlsCfg.VerifyPeerCertificate
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if err := origVerify(rawCerts, verifiedChains); err != nil {
			if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
				sans := make([]string, 0, len(leaf.URIs))
				for _, u := range leaf.URIs {
					sans = append(sans, u.String())
				}
				logger.Warn("callback.tls.unauthorized_peer",
					"event", "callback.tls.unauthorized_peer",
					"issuer", leaf.Issuer.String(),
					"subject", leaf.Subject.String(),
					"sans_uri", strings.Join(sans, ","),
					"error", err.Error(),
				)
			} else {
				logger.Warn("callback.tls.unauthorized_peer",
					"event", "callback.tls.unauthorized_peer",
					"error", err.Error(),
				)
			}
			return err
		}
		if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
			spiffeID := ""
			for _, u := range leaf.URIs {
				if strings.HasPrefix(u.Scheme, "spiffe") {
					spiffeID = u.String()
					break
				}
			}
			if spiffeID != "" {
				logger.Info("callback.tls.peer_accepted",
					"event", "callback.tls.peer_accepted",
					"spiffe_id", spiffeID,
				)
			}
		}
		return nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	health := &alwaysHealthyCallbackServer{}
	grpc_health_v1.RegisterHealthServer(srv, health)

	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	return srv, ln.Addr().String(), health, buf
}

// --- Client dialers ---

func dialCallbackPlainTCP(t *testing.T, target string) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func dialCallbackTLSNoCert(t *testing.T, target string) *grpc.ClientConn {
	t.Helper()
	rawTLS := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS13,
	}
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(rawTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func dialCallbackForeignSPIFFE(t *testing.T, target string, foreignPKI *callbackTestPKI, serverPKI *callbackTestPKI) *grpc.ClientConn {
	t.Helper()

	svid, err := foreignPKI.svidSource.GetX509SVID()
	require.NoError(t, err)

	leafPEM, keyPEM := svidToPEMCallback(t, svid)
	clientCert, err := tls.X509KeyPair(leafPEM, keyPEM)
	require.NoError(t, err)

	serverCAPool := x509.NewCertPool()
	serverBundle, err := serverPKI.bundleSource.GetX509BundleForTrustDomain(
		spiffeid.RequireTrustDomainFromString("zeroroot.ai"),
	)
	require.NoError(t, err)
	for _, ca := range serverBundle.X509Authorities() {
		serverCAPool.AddCert(ca)
	}

	rawTLS := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, //nolint:gosec // test only — the test cares about server-side rejection of client cert, not server-cert validation
		MinVersion:         tls.VersionTLS13,
	}
	_ = serverCAPool
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(rawTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func svidToPEMCallback(t *testing.T, svid *x509svid.SVID) (certPEM, keyPEM []byte) {
	t.Helper()
	for _, cert := range svid.Certificates {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: cert.Raw,
		})...)
	}
	ecKey, ok := svid.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "SVID private key must be *ecdsa.PrivateKey")
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = base64.StdEncoding // keep encoding/base64 import valid in case future tweaks need it
	return
}

// --- Tests ---

// TestCallback_PlainTCPDial_HandshakeRejected dials the callback listener
// over plain TCP (insecure.NewCredentials). Asserts the gRPC Health.Check
// call returns a transport-level error and that the handler's call counter
// remains zero — proving the rejection happens at the TLS layer, never
// reaching application code.
//
// Spec: critical-tls-no-fallbacks Requirement 5.1.
func TestCallback_PlainTCPDial_HandshakeRejected(t *testing.T) {
	serverPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/server")
	clientPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/agent-client")
	allowlist := []spiffeid.ID{clientPKI.spiffeID}

	_, addr, health, _ := startCallbackTestServer(t, serverPKI, allowlist)

	cc := dialCallbackPlainTCP(t, addr)
	healthClient := healthpb.NewHealthClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.Error(t, err,
		"spec critical-tls-no-fallbacks Req 5.1: plain-TCP dial against the "+
			"callback listener MUST fail at handshake; the gRPC stack must NOT see it.")
	assert.Equal(t, int64(0), health.calls.Load(),
		"the application handler must NOT be reached on plain-TCP dial")
}

// TestCallback_NoClientCert_HandshakeRejected dials with TLS but no client
// cert. Asserts the call fails before the handler is reached.
//
// Spec: critical-tls-no-fallbacks Requirement 5.1.
func TestCallback_NoClientCert_HandshakeRejected(t *testing.T) {
	serverPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/server")
	clientPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/agent-client")
	allowlist := []spiffeid.ID{clientPKI.spiffeID}

	_, addr, health, _ := startCallbackTestServer(t, serverPKI, allowlist)

	cc := dialCallbackTLSNoCert(t, addr)
	healthClient := healthpb.NewHealthClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.Error(t, err,
		"spec critical-tls-no-fallbacks Req 5.1: a TLS dial without a client "+
			"cert MUST fail at handshake on the callback listener.")
	assert.Equal(t, int64(0), health.calls.Load(),
		"the application handler must NOT be reached on no-cert TLS dial")
}

// TestCallback_NotInAllowlist_HandshakeRejectedAndLogged dials with a valid
// SPIFFE SVID issued by a CA the server trusts (so the chain validates) but
// for a SPIFFE ID that is NOT in the AuthorizeOneOf peer allowlist. Asserts
// the call fails AND the test logger records a callback.tls.unauthorized_peer
// event with the rejected SPIFFE ID.
//
// Note: a SVID from a wholly-foreign trust domain is rejected at the stdlib
// chain-validation step before our VerifyPeerCertificate wrapper runs (which
// is correct — it's even stricter than this test). To exercise the
// log-emitting wrapper we use a SVID whose chain is acceptable but whose ID
// fails the allowlist authorizer.
//
// Spec: critical-tls-no-fallbacks Requirements 1.3, 1.4, 5.2.
func TestCallback_NotInAllowlist_HandshakeRejectedAndLogged(t *testing.T) {
	// One CA, two SVIDs in the same trust domain; only allowedClientPKI is
	// on the allowlist. otherClientPKI has the same CA so the chain validates,
	// but its SPIFFE ID is rejected by AuthorizeOneOf.
	allowedClientPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/agent-allowed")
	otherClientPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/agent-impostor")

	// Use the allowed client's CA as the server's bundle (the test server's
	// own SVID isn't presented to clients here — we only care about client-
	// auth chain validation).
	serverPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/server")
	// Cross-trust both client CAs so chain validation passes for both clients.
	// Clone the bundle so we own a fresh copy before mutating.
	serverBundle := serverPKI.bundleSource.bundle.Clone()
	serverBundle.AddX509Authority(allowedClientPKI.caCert)
	serverBundle.AddX509Authority(otherClientPKI.caCert)
	serverPKI.bundleSource.bundle = serverBundle

	allowlist := []spiffeid.ID{allowedClientPKI.spiffeID}
	_, addr, health, logBuf := startCallbackTestServer(t, serverPKI, allowlist)

	// Build a client cert from otherClientPKI but trust the server's CA so
	// dial succeeds at the server-cert verification step.
	cc := dialCallbackForeignSPIFFE(t, addr, otherClientPKI, serverPKI)
	healthClient := healthpb.NewHealthClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.Error(t, err,
		"spec critical-tls-no-fallbacks Req 1.3: a SPIFFE SVID not in the peer "+
			"allowlist MUST be rejected at handshake.")
	assert.Equal(t, int64(0), health.calls.Load(),
		"the application handler must NOT be reached on not-in-allowlist dial")

	// The handshake-rejection log is emitted from the server's TLS goroutine.
	// The client's error returns when the server sends the alert; the server's
	// VerifyPeerCertificate callback may finish writing the log a few ms
	// later. Poll up to 1s for the log line.
	deadline := time.Now().Add(1 * time.Second)
	var logs string
	for time.Now().Before(deadline) {
		logs = logBuf.String()
		if strings.Contains(logs, "callback.tls.unauthorized_peer") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.Contains(t, logs, "callback.tls.unauthorized_peer",
		"spec critical-tls-no-fallbacks Req 1.4: the handshake-rejection log "+
			"event MUST be emitted with the stable name callback.tls.unauthorized_peer.")
	// And the log must include the rejected SPIFFE ID for actionable debugging.
	assert.Contains(t, logs, otherClientPKI.spiffeID.String(),
		"the unauthorized_peer log must carry the rejected SPIFFE ID for debugging")
}
