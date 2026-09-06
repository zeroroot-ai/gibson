// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Regression tests for identity-assertion-gaps finding 2
// (GHSA-cwgm-qw3c-4ph7 / GHSA-2mmp-x243-f69j): the harness callback listener
// applied ONLY the header-trusting auth.UnaryServerInterceptor()/
// StreamServerInterceptor() behind SPIFFE mTLS AuthorizeOneOf(peerSVIDs...),
// with no per-peer, per-method policy. The DENYLIST that replaced it named only
// the dashboard, leaving the Envoy and daemon-loopback peers — and any peer
// added to GIBSON_CALLBACK_PEER_SVIDS afterwards — with unbounded
// (subject, tenant) assertion across every RPC on the service, GetCredential
// included.
//
// The classification table and its guard tests live in
// callback_method_policy_test.go; this file covers the interceptor plumbing
// (unary, stream, and a real TLS handshake).

package harness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// --- Unit tests: peerSPIFFEID extraction (no TLS needed) ---

// fakeAuthInfo implements credentials.AuthInfo without being TLSInfo, for
// exercising peerSPIFFEID's type-assertion failure branch.
type fakeAuthInfo struct{}

func (fakeAuthInfo) AuthType() string { return "fake" }

func certWithURIs(uris ...string) *x509.Certificate {
	parsed := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		pu, err := url.Parse(u)
		if err != nil {
			panic(err)
		}
		parsed = append(parsed, pu)
	}
	return &x509.Certificate{URIs: parsed}
}

func TestPeerSPIFFEID_NoPeerInContext(t *testing.T) {
	svid, ok := peerSPIFFEID(context.Background())
	assert.False(t, ok)
	assert.Empty(t, svid)
}

func TestPeerSPIFFEID_NonTLSAuthInfo(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: fakeAuthInfo{}})
	svid, ok := peerSPIFFEID(ctx)
	assert.False(t, ok)
	assert.Empty(t, svid)
}

func TestPeerSPIFFEID_TLSInfoNoCertificates(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: nil}},
	})
	svid, ok := peerSPIFFEID(ctx)
	assert.False(t, ok)
	assert.Empty(t, svid)
}

func TestPeerSPIFFEID_CertWithoutSPIFFEURI(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certWithURIs("https://example.com/not-spiffe")},
		}},
	})
	svid, ok := peerSPIFFEID(ctx)
	assert.False(t, ok)
	assert.Empty(t, svid)
}

func TestPeerSPIFFEID_FindsSPIFFEURI(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certWithURIs(callbackEnvoySVID)},
		}},
	})
	svid, ok := peerSPIFFEID(ctx)
	require.True(t, ok)
	assert.Equal(t, callbackEnvoySVID, svid)
}

// --- Interceptor tests ---
//
// HarnessCallbackService has streaming RPCs (LLMStream, CallToolProtoStream,
// ToolResults), so the stream interceptor half needs its own coverage —
// exercised directly against a minimal fake grpc.ServerStream, mirroring the
// serverStreamCtxOverride pattern in internal/server/daemon/grpc.go.

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

func ctxWithSVID(svid string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certWithURIs(svid)},
		}},
	})
}

// ctxWithNoTLSPeer models a connection the interceptor cannot derive a SPIFFE
// identity from.
func ctxWithNoTLSPeer() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: fakeAuthInfo{}})
}

func TestCallbackPeerAuthzInterceptors_UnaryDeniesUnknownPeer(t *testing.T) {
	logger, _ := newBufferLogger()
	unary, _ := callbackPeerAuthzInterceptors(logger, true)

	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return nil, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/GetCredential"}

	_, err := unary(ctxWithSVID("spiffe://zeroroot.ai/platform/some-new-thing"), nil, info, handler)
	require.Error(t, err, "REGRESSION (GHSA-cwgm-qw3c-4ph7): an unclassified peer SVID must be denied, "+
		"not defaulted to allowed")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, handlerCalled, "the handler must NOT be invoked for a denied peer")
}

func TestCallbackPeerAuthzInterceptors_UnaryDeniesUnresolvableSVID(t *testing.T) {
	logger, _ := newBufferLogger()
	unary, _ := callbackPeerAuthzInterceptors(logger, true)

	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return nil, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/GetCredential"}

	_, err := unary(ctxWithNoTLSPeer(), nil, info, handler)
	require.Error(t, err, "REGRESSION (GHSA-cwgm-qw3c-4ph7): peerSPIFFEID failing to resolve must DENY. "+
		"The old interceptors only ran the check when ok==true, so an unidentifiable peer passed straight "+
		"through to the header-trusting interceptor")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, handlerCalled)
}

func TestCallbackPeerAuthzInterceptors_UnaryAllowsAgentPeerInPolicy(t *testing.T) {
	logger, _ := newBufferLogger()
	unary, _ := callbackPeerAuthzInterceptors(logger, true)

	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return nil, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/LLMComplete"}

	_, err := unary(ctxWithSVID(callbackEnvoySVID), nil, info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled, "the legitimate in-mission callback path must not regress")
}

func TestCallbackPeerAuthzInterceptors_StreamDeniesDashboard(t *testing.T) {
	logger, _ := newBufferLogger()
	_, streamInterceptor := callbackPeerAuthzInterceptors(logger, true)

	ss := &fakeServerStream{ctx: ctxWithSVID(callbackDashboardSVID)}
	handlerCalled := false
	handler := func(_ any, _ grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/LLMStream"}

	err := streamInterceptor(nil, ss, info, handler)
	require.Error(t, err, "the dashboard SVID must be denied on streaming RPCs too, not just unary ones")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, handlerCalled, "the stream handler must NOT be invoked for a denied peer")
}

func TestCallbackPeerAuthzInterceptors_StreamDeniesUnknownPeer(t *testing.T) {
	logger, _ := newBufferLogger()
	_, streamInterceptor := callbackPeerAuthzInterceptors(logger, true)

	ss := &fakeServerStream{ctx: ctxWithSVID("spiffe://zeroroot.ai/platform/some-new-thing")}
	handlerCalled := false
	handler := func(_ any, _ grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/LLMStream"}

	err := streamInterceptor(nil, ss, info, handler)
	require.Error(t, err, "REGRESSION (GHSA-cwgm-qw3c-4ph7): an unclassified peer must be denied on "+
		"streaming RPCs as well")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, handlerCalled)
}

func TestCallbackPeerAuthzInterceptors_StreamAllowsAgentPeer(t *testing.T) {
	logger, _ := newBufferLogger()
	_, streamInterceptor := callbackPeerAuthzInterceptors(logger, true)

	ss := &fakeServerStream{ctx: ctxWithSVID(callbackEnvoySVID)}
	handlerCalled := false
	handler := func(_ any, _ grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/LLMStream"}

	err := streamInterceptor(nil, ss, info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled, "an agent-callback peer's stream handler must still be invoked")
}

// TestCallbackPeerAuthzInterceptors_NoEnforcementWithoutSPIFFE documents — and
// pins — the one posture where the policy does not apply: the plaintext loopback
// dev/test bind, which has no peer certificate to derive an identity from.
// rejectNonLoopbackWithoutSPIFFE (listener_guard.go) is what keeps that posture
// off any non-loopback address; every production bind constructs these
// interceptors with enforce=true (CallbackServer.Start passes
// s.spiffeSource != nil).
func TestCallbackPeerAuthzInterceptors_NoEnforcementWithoutSPIFFE(t *testing.T) {
	logger, _ := newBufferLogger()
	unary, _ := callbackPeerAuthzInterceptors(logger, false)

	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return nil, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.harness.v1.HarnessCallbackService/GetCredential"}

	_, err := unary(context.Background(), nil, info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

// --- Integration test: real TLS handshake + real interceptor chain ---

// alwaysHealthyCallbackServer, callbackTestPKI, newCallbackTestPKI, and
// svidToPEMCallback are defined in callback_server_tls_test.go and reused
// here — same package, same test binary.

// startCallbackTestServerWithInterceptor stands up a gRPC server chaining the
// REAL callbackPeerAuthzInterceptors ahead of a minimal Health handler, so this
// test exercises the exact interceptor Start() wires in production — not a
// reimplementation of it. clientPKIs are added to the server's trust bundle so
// their mTLS handshakes succeed (whether or not they end up in allowlist),
// letting the test isolate the interceptor's application-layer decision from
// TLS-layer AuthorizeOneOf rejection.
func startCallbackTestServerWithInterceptor(t *testing.T, serverPKI *callbackTestPKI, clientPKIs []*callbackTestPKI, allowlist []spiffeid.ID) (addr string, health *alwaysHealthyCallbackServer) {
	t.Helper()

	logger, _ := newBufferLogger()
	unary, _ := callbackPeerAuthzInterceptors(logger, true)

	serverBundle := serverPKI.bundleSource.bundle.Clone()
	for _, pki := range clientPKIs {
		serverBundle.AddX509Authority(pki.caCert)
	}
	serverPKI.bundleSource.bundle = serverBundle

	tlsCfg := tlsconfig.MTLSServerConfig(serverPKI.svidSource, serverPKI.bundleSource, tlsconfig.AuthorizeOneOf(allowlist...))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(unary),
	)
	h := &alwaysHealthyCallbackServer{}
	healthpb.RegisterHealthServer(srv, h)

	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	return ln.Addr().String(), h
}

// dialCallbackAsClient dials presenting clientPKI's SVID as the client
// certificate, so the SERVER's mTLS validation (AuthorizeOneOf + the
// application-layer peer-authz interceptor) is exercised for real — that is what
// this test suite cares about. Server-certificate validation on the client side
// is skipped (InsecureSkipVerify), matching dialCallbackForeignSPIFFE in
// callback_server_tls_test.go: the synthetic leaf certs here carry only a SPIFFE
// URI SAN (no DNS/IP SAN for "127.0.0.1"), and standard hostname verification is
// orthogonal to what these tests assert.
func dialCallbackAsClient(t *testing.T, clientPKI, _ *callbackTestPKI, addr string) *grpc.ClientConn {
	t.Helper()

	svid, err := clientPKI.svidSource.GetX509SVID()
	require.NoError(t, err)
	leafPEM, keyPEM := svidToPEMCallback(t, svid)
	clientCert, err := tls.X509KeyPair(leafPEM, keyPEM)
	require.NoError(t, err)

	rawTLS := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, //nolint:gosec // test only — see doc comment above
		MinVersion:         tls.VersionTLS13,
	}
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(rawTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// TestCallback_DashboardSVID_DeniedAtApplicationLayer: the dashboard's SVID is a
// legitimate, allow-listed TLS peer (the mTLS handshake succeeds — this is NOT a
// transport-level rejection like the tests in callback_server_tls_test.go), but
// the request must still be rejected before the handler runs.
func TestCallback_DashboardSVID_DeniedAtApplicationLayer(t *testing.T) {
	serverPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/server")
	dashboardPKI := newCallbackTestPKI(t, "zeroroot.ai", "/platform/dashboard")
	allowlist := []spiffeid.ID{dashboardPKI.spiffeID}

	addr, health := startCallbackTestServerWithInterceptor(t, serverPKI, []*callbackTestPKI{dashboardPKI}, allowlist)

	cc := dialCallbackAsClient(t, dashboardPKI, serverPKI, addr)
	healthClient := healthpb.NewHealthClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.Error(t, err, "the dashboard SVID must be denied at the application layer even though it "+
		"is TLS-allow-listed")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, int64(0), health.calls.Load(),
		"the handler must NOT be reached for a peer denied by callbackPeerAuthzInterceptors")
}

// TestCallback_UnclassifiedSVID_DeniedAtApplicationLayer is the core inversion
// test. This peer is TLS-allow-listed (it is in GIBSON_CALLBACK_PEER_SVIDS, so
// the handshake succeeds) but has no method policy. Under the old DENYLIST it
// reached the handler with full power over all 41 RPCs; under the allowlist it
// gets nothing.
func TestCallback_UnclassifiedSVID_DeniedAtApplicationLayer(t *testing.T) {
	serverPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/server")
	newPeerPKI := newCallbackTestPKI(t, "zeroroot.ai", "/platform/some-new-thing")
	allowlist := []spiffeid.ID{newPeerPKI.spiffeID}

	addr, health := startCallbackTestServerWithInterceptor(t, serverPKI, []*callbackTestPKI{newPeerPKI}, allowlist)

	cc := dialCallbackAsClient(t, newPeerPKI, serverPKI, addr)
	healthClient := healthpb.NewHealthClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.Error(t, err, "REGRESSION (GHSA-cwgm-qw3c-4ph7): a TLS-allow-listed peer with no method "+
		"policy must be denied. Under the denylist ANY peer it did not name got full access by default — "+
		"that is the failure mode this inversion exists to close")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, int64(0), health.calls.Load())
}

// TestCallback_EnvoySVID_ReachesHandler is the paired control: the Envoy peer
// passes both the TLS handshake AND the method policy for a method inside its
// policy, proving the fix does not regress the live mission callback path.
func TestCallback_EnvoySVID_ReachesHandler(t *testing.T) {
	serverPKI := newCallbackTestPKI(t, "zeroroot.ai", "/callback/server")
	envoyPKI := newCallbackTestPKI(t, "zeroroot.ai", "/platform/envoy")
	allowlist := []spiffeid.ID{envoyPKI.spiffeID}

	addr, health := startCallbackTestServerWithInterceptor(t, serverPKI, []*callbackTestPKI{envoyPKI}, allowlist)

	cc := dialCallbackAsClient(t, envoyPKI, serverPKI, addr)
	healthClient := healthpb.NewHealthClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err, "the Envoy peer must still reach its classified methods")
	assert.Equal(t, int64(1), health.calls.Load())
}
