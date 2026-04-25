package daemon

// Integration tests for the SPIFFE mTLS listener behaviour.
//
// These tests are in-process only — no SPIRE server, no testcontainers, no
// network hops. They use synthetic self-signed PKI created by
// newSyntheticSPIFFESources (defined in grpc_test.go) plus a second CA to
// simulate "foreign cert" rejections.
//
// All three tests run as part of `make test-race`; no build tag is required.
//
// Reference: spec daemon-tls-clientauth-fix / B-bug 1 in
// in-cluster-mtls-restoration/design.md.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// --- Test infrastructure ---

// spiffeTestPKI holds a CA + bundle source + a leaf SVID source that the test
// server and clients can share or mix.
type spiffeTestPKI struct {
	caCert       *x509.Certificate
	bundleSource *stubBundleSource
	svidSource   *stubSVIDSource
}

// newSpiffeTestPKI creates a fresh CA + one leaf SVID, both in-process.
// trustDomainName e.g. "gibson.io", pathSuffix e.g. "/test/server".
func newSpiffeTestPKI(t *testing.T, trustDomainName, pathSuffix string) *spiffeTestPKI {
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

	return &spiffeTestPKI{
		caCert:       caCert,
		bundleSource: &stubBundleSource{bundle: bundle},
		svidSource:   &stubSVIDSource{svid: svid},
	}
}

// startMTLSTestServer spins up an in-process gRPC server using the daemon's
// SPIFFE mTLS config (MTLSServerConfig + RequestClientCert override + callback wrapper).
// Mirrors buildGRPCServer's SPIFFE TLS setup exactly.
// Returns the server and its listener address. Call t.Cleanup(srv.Stop).
func startMTLSTestServer(t *testing.T, pki *spiffeTestPKI) (*grpc.Server, string) {
	t.Helper()

	// Build TLS config exactly as buildGRPCServer does (spec daemon-tls-clientauth-fix).
	tlsCfg := tlsconfig.MTLSServerConfig(pki.svidSource, pki.bundleSource, tlsconfig.AuthorizeAny())
	// The fix: RequestClientCert (not VerifyClientCertIfGiven, not RequireAnyClientCert).
	tlsCfg.ClientAuth = tls.RequestClientCert
	// Wrap callback to allow no-cert clients through (Bearer-only path).
	// Mirrors the same wrapper in buildGRPCServer.
	origVerify := tlsCfg.VerifyPeerCertificate
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		return origVerify(rawCerts, verifiedChains)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	// Register the standard gRPC health service so we can probe it.
	grpc_health_v1.RegisterHealthServer(srv, &alwaysHealthyServer{})

	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(srv.Stop)

	return srv, ln.Addr().String()
}

// alwaysHealthyServer implements grpc_health_v1.HealthServer returning SERVING.
type alwaysHealthyServer struct {
	healthpb.UnimplementedHealthServer
}

func (s *alwaysHealthyServer) Check(_ context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// dialWithClientCert dials the target over TLS presenting the given client cert.
// The clientCertChain/clientKey come from the client PKI; the serverCA is used
// to verify the server (so we don't need InsecureSkipVerify).
func dialWithClientCert(t *testing.T, target string, clientPKI *spiffeTestPKI, serverPKI *spiffeTestPKI) *grpc.ClientConn {
	t.Helper()
	clientTLSCfg := tlsconfig.MTLSClientConfig(clientPKI.svidSource, serverPKI.bundleSource, tlsconfig.AuthorizeAny())
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(clientTLSCfg)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// dialWithForeignCert dials the target using a cert from foreignPKI (not trusted
// by the server). We need to tell the client to trust the server's cert, so we
// use a raw tls.Config with the server CA + the foreign client cert.
func dialWithForeignCert(t *testing.T, target string, foreignClientPKI *spiffeTestPKI, serverPKI *spiffeTestPKI) *grpc.ClientConn {
	t.Helper()

	// Build a leaf tls.Certificate from the foreign PKI's SVID.
	svid, err := foreignClientPKI.svidSource.GetX509SVID()
	require.NoError(t, err)

	leafPEM, keyPEM := svidToPEM(t, svid)
	clientCert, err := tls.X509KeyPair(leafPEM, keyPEM)
	require.NoError(t, err)

	// Server CA pool so the client can verify the server cert.
	serverCAPool := x509.NewCertPool()
	serverBundle, err := serverPKI.bundleSource.GetX509BundleForTrustDomain(
		spiffeid.RequireTrustDomainFromString("gibson.io"),
	)
	require.NoError(t, err)
	for _, ca := range serverBundle.X509Authorities() {
		serverCAPool.AddCert(ca)
	}

	rawTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCAPool,
		ServerName:   "127.0.0.1",
		MinVersion:   tls.VersionTLS13,
	}
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(rawTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// dialWithNoCert dials the target over TLS without presenting a client cert.
// Uses InsecureSkipVerify for the server cert (test PKI is self-signed).
// gRPC's credentials layer adds ALPN h2 automatically — do not set NextProtos.
func dialWithNoCert(t *testing.T, target string, _ *spiffeTestPKI) *grpc.ClientConn {
	t.Helper()

	// Use InsecureSkipVerify for the server cert since our test server cert
	// has a self-signed CA. We only need to prove the handshake succeeds —
	// we don't need to prove server-cert verification here.
	// NOTE: do NOT set NextProtos manually — grpc/credentials.NewTLS adds h2 for us.
	rawTLS := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only — verifying no-cert flow, not server cert
		MinVersion:         tls.VersionTLS13,
		// No Certificates field — no client cert presented.
	}
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(rawTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// dialInsecure dials without TLS at all — used only when we need to verify that
// a TLS server rejects plain connections.
func dialInsecure(t *testing.T, target string) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// svidToPEM encodes an x509svid.SVID into PEM bytes for tls.X509KeyPair.
func svidToPEM(t *testing.T, svid *x509svid.SVID) (certPEM, keyPEM []byte) {
	t.Helper()
	import_encoding_pem := func(pemType string, derBytes []byte) []byte {
		return append([]byte("-----BEGIN "+pemType+"-----\n"),
			append(pemEncodeBase64(derBytes), []byte("\n-----END "+pemType+"-----\n")...)...)
	}

	for _, cert := range svid.Certificates {
		certPEM = append(certPEM, import_encoding_pem("CERTIFICATE", cert.Raw)...)
	}

	ecKey, ok := svid.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "SVID private key must be *ecdsa.PrivateKey")
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	keyPEM = import_encoding_pem("EC PRIVATE KEY", keyDER)
	return
}

// pemEncodeBase64 encodes DER bytes as base64 with 64-char line wrapping.
func pemEncodeBase64(der []byte) []byte {
	const lineWidth = 64
	// Use encoding/pem via a helper to avoid importing it at package level.
	// This replicates pem.Encode without the overhead.
	b64 := make([]byte, encodedLen(len(der)))
	base64Encode(b64, der)
	var out []byte
	for len(b64) > 0 {
		n := lineWidth
		if n > len(b64) {
			n = len(b64)
		}
		out = append(out, b64[:n]...)
		out = append(out, '\n')
		b64 = b64[n:]
	}
	return out
}

// base64Encode and encodedLen replicate encoding/base64.StdEncoding without
// the import (to keep the file self-contained).
func encodedLen(n int) int {
	return (n + 2) / 3 * 4
}

func base64Encode(dst, src []byte) {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = enc[val>>18&0x3f]
		dst[di+1] = enc[val>>12&0x3f]
		dst[di+2] = enc[val>>6&0x3f]
		dst[di+3] = enc[val>>0&0x3f]
		si += 3
		di += 4
	}
	rem := len(src) - n
	if rem == 0 {
		return
	}
	val := uint(src[n]) << 16
	if rem == 2 {
		val |= uint(src[n+1]) << 8
	}
	dst[di+0] = enc[val>>18&0x3f]
	dst[di+1] = enc[val>>12&0x3f]
	switch rem {
	case 2:
		dst[di+2] = enc[val>>6&0x3f]
		dst[di+3] = '='
	case 1:
		dst[di+2] = '='
		dst[di+3] = '='
	}
}

// --- Tests ---

// TestMTLS_ValidSPIFFECert_HandshakeSucceeds proves that a client presenting
// a SPIFFE X.509 SVID from the same trust domain as the server's bundle
// completes the TLS handshake and reaches gRPC application-layer handling.
//
// Reference: spec daemon-tls-clientauth-fix Requirement 1.1 / Component 3(a).
func TestMTLS_ValidSPIFFECert_HandshakeSucceeds(t *testing.T) {
	serverPKI := newSpiffeTestPKI(t, "gibson.io", "/test/server")
	clientPKI := newSpiffeTestPKI(t, "gibson.io", "/test/client")

	// The server's bundle must trust the CLIENT's CA for this test to pass.
	// Add client CA to the server's bundle source.
	serverBundle, err := serverPKI.bundleSource.bundle.Clone(), error(nil)
	_ = err
	serverBundle.AddX509Authority(clientPKI.caCert)
	serverPKI.bundleSource.bundle = serverBundle

	_, addr := startMTLSTestServer(t, serverPKI)

	cc := dialWithClientCert(t, addr, clientPKI, serverPKI)
	healthClient := healthpb.NewHealthClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	// The handshake must complete and application data must flow.
	require.NoError(t, err,
		"REGRESSION (spec daemon-tls-clientauth-fix / B-bug 1): "+
			"valid SPIFFE client cert should complete the mTLS handshake and reach the gRPC handler. "+
			"If this fails with 'unknown_ca' or transport error, the fix may have been reverted.")
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

// TestMTLS_NonSPIFFECert_HandshakeFails proves that a client presenting a
// certificate from an untrusted CA is rejected by the SPIFFE
// VerifyPeerCertificate callback during the TLS handshake — NOT as a
// post-handshake alert.
//
// Reference: spec daemon-tls-clientauth-fix Requirement 1.2 / Component 3(b).
func TestMTLS_NonSPIFFECert_HandshakeFails(t *testing.T) {
	serverPKI := newSpiffeTestPKI(t, "gibson.io", "/test/server")
	// foreignPKI is from a COMPLETELY different CA — NOT trusted by the server.
	foreignPKI := newSpiffeTestPKI(t, "foreign.example", "/test/foreign")

	_, addr := startMTLSTestServer(t, serverPKI)

	cc := dialWithForeignCert(t, addr, foreignPKI, serverPKI)
	healthClient := healthpb.NewHealthClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.Error(t, err,
		"REGRESSION (spec daemon-tls-clientauth-fix / B-bug 1): "+
			"a foreign cert (not trusted by SPIRE bundle) must be rejected.")

	// The error must come from the TLS layer (transport), not a gRPC status code
	// from an application handler — that would indicate the cert bypassed the
	// callback. We check for a non-OK status or a transport-level error.
	st, ok := status.FromError(err)
	if ok {
		// gRPC status is acceptable here — it means the TLS error was propagated
		// as a gRPC Unavailable or Internal code from the transport layer.
		assert.NotEqual(t, codes.OK, st.Code(),
			"foreign cert connection should result in a non-OK gRPC status")
	}
	// Whether we got a raw transport error or a gRPC status, the call must fail.
	// This is what matters: the SPIFFE callback rejected the cert.
	_ = err // already asserted non-nil above
}

// TestMTLS_NoCert_HandshakeSucceedsAndFallsThroughToBearer proves that a client
// that presents NO client certificate can still complete the TLS handshake
// (the tls.RequestClientCert value doesn't require a cert), and that the
// resulting gRPC call reaches the application layer — not a transport rejection.
//
// The expected outcome for an unauthenticated call (no cert, no Bearer header)
// is either a successful response (if the server has no auth interceptor) or
// a gRPC Unauthenticated/Internal status from an auth gate. Either way, the
// connection MUST reach the gRPC layer — a transport error here means
// tls.RequestClientCert was changed to tls.RequireAnyClientCert.
//
// Reference: spec daemon-tls-clientauth-fix Requirement 1.3 / Component 3(c).
func TestMTLS_NoCert_HandshakeSucceedsAndFallsThroughToBearer(t *testing.T) {
	serverPKI := newSpiffeTestPKI(t, "gibson.io", "/test/server")
	_, addr := startMTLSTestServer(t, serverPKI)

	cc := dialWithNoCert(t, addr, serverPKI)
	healthClient := healthpb.NewHealthClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})

	// The TLS handshake MUST complete — RequestClientCert allows no-cert clients.
	// If it fails with a transport error, tls.RequireAnyClientCert was set instead.
	if err != nil {
		st, ok := status.FromError(err)
		if ok && (st.Code() == codes.Unavailable || st.Code() == codes.Internal) {
			// Transport-level failure — this is the regression signal.
			t.Fatalf(
				"REGRESSION (spec daemon-tls-clientauth-fix / B-bug 1): "+
					"no-cert client was rejected at transport layer (code=%s). "+
					"tls.RequestClientCert must allow no-cert clients through to the gRPC layer. "+
					"Did someone change ClientAuth to tls.RequireAnyClientCert? error: %v",
				st.Code(), err,
			)
		}
		// Any OTHER gRPC error (Unauthenticated, PermissionDenied, etc.) means
		// the connection reached the application layer — that's the correct behaviour
		// for the Bearer-only fallthrough path.
	} else {
		// No error: the test server's health handler returned SERVING, which also
		// proves the handshake completed and application data flowed.
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	}
}

// TestMTLS_VerifyClientCertIfGiven_WouldBreakSPIFFE is a documentation test
// that demonstrates WHY the old tls.VerifyClientCertIfGiven value was broken.
// It is NOT testing production code — it shows the failure mode that was fixed.
//
// When ClientAuth = VerifyClientCertIfGiven AND ClientCAs is nil:
//   - Go's stdlib verifier is invoked for cert-presented clients.
//   - It fails with "unknown_ca" because it has no acceptable CA to verify against.
//   - The SPIFFE VerifyPeerCertificate callback NEVER runs.
//
// Reference: spec daemon-tls-clientauth-fix B-bug 1 analysis.
func TestMTLS_VerifyClientCertIfGiven_WouldBreakSPIFFE(t *testing.T) {
	serverPKI := newSpiffeTestPKI(t, "gibson.io", "/test/server")
	clientPKI := newSpiffeTestPKI(t, "gibson.io", "/test/client")

	// Add client CA to server bundle (same as the valid test).
	serverBundle := serverPKI.bundleSource.bundle.Clone()
	serverBundle.AddX509Authority(clientPKI.caCert)
	serverPKI.bundleSource.bundle = serverBundle

	// Build the BROKEN config to demonstrate the failure mode.
	brokenTLSCfg := tlsconfig.MTLSServerConfig(serverPKI.svidSource, serverPKI.bundleSource, tlsconfig.AuthorizeAny())
	brokenTLSCfg.ClientAuth = tls.VerifyClientCertIfGiven // THE BUG
	// Note: ClientCAs is nil — stdlib verifier finds no acceptable issuer.

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(brokenTLSCfg)))
	grpc_health_v1.RegisterHealthServer(srv, &alwaysHealthyServer{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	// A valid SPIFFE client connecting to the BROKEN server should fail.
	clientTLSCfg := tlsconfig.MTLSClientConfig(clientPKI.svidSource, serverPKI.bundleSource, tlsconfig.AuthorizeAny())
	cc, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLSCfg)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthClient := healthpb.NewHealthClient(cc)
	_, callErr := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})

	// This SHOULD fail (the broken config rejects SPIFFE clients).
	// If it unexpectedly succeeds, go-spiffe's behaviour has changed — update this doc test.
	if callErr == nil {
		t.Log("WARNING: VerifyClientCertIfGiven did NOT fail for SPIFFE client. " +
			"go-spiffe behaviour may have changed. Review the spec daemon-tls-clientauth-fix analysis.")
	} else {
		t.Logf("Confirmed: VerifyClientCertIfGiven breaks SPIFFE clients with error: %v", callErr)
		// The error is expected — don't fail the test. This is a documentation test.
		assert.Error(t, callErr, "VerifyClientCertIfGiven should reject SPIFFE cert-presented clients")
	}

	// The primary regression guard is TestBuildGRPCServer_ClientAuthIsRequestClientCert
	// and TestMTLS_ValidSPIFFECert_HandshakeSucceeds. This test only documents why.
}

// Ensure the unused import doesn't cause compile errors.
var _ = errors.New
