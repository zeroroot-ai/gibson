// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPKI issues SPIFFE SVIDs from one CA.
type testPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	bundle *x509bundle.Bundle
	td     spiffeid.TrustDomain
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	td := spiffeid.RequireTrustDomainFromString("example.org")
	return &testPKI{ca: ca, caKey: key, td: td, bundle: x509bundle.FromX509Authorities(td, []*x509.Certificate{ca})}
}

// svid issues the SVID of one SPIFFE ID.
func (p *testPKI) svid(t *testing.T, id spiffeid.ID) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	u, err := url.Parse(id.String())
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	s, err := x509svid.ParseRaw(der, keyDER)
	require.NoError(t, err)
	return s
}

type pkiSource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s pkiSource) Close() error                         { return nil }
func (s pkiSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }
func (s pkiSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

// The inbound listener serves the Edge identity only. A peer with another SPIFFE ID
// of the same trust domain, for example the Agent gateway, cannot finish the TLS
// handshake, so it reaches no handler.
func TestInboundListener_RefusesAPeerThatIsNotTheEdge(t *testing.T) {
	pki := newTestPKI(t)
	edge := spiffeid.RequireFromPath(pki.td, "/platform/envoy")
	gateway := spiffeid.RequireFromPath(pki.td, "/platform/agentgateway")
	server := spiffeid.RequireFromPath(pki.td, "/gibson/daemon")

	d := a2aListenerDaemon(t, func(d *daemonImpl) {
		d.spiffeX509Source = pkiSource{svid: pki.svid(t, server), bundle: pki.bundle}
	})
	cfg, err := d.peerTLSConfig("A2A inbound listener", edge)
	require.NoError(t, err)

	lis, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	reached := make(chan struct{}, 4)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached <- struct{}{}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })

	get := func(peer spiffeid.ID) error {
		client := pkiSource{svid: pki.svid(t, peer), bundle: pki.bundle}
		cc := tlsconfig.MTLSClientConfig(client, client, tlsconfig.AuthorizeID(server))
		hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			TLSClientConfig: cc,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, lis.Addr().String())
			},
		}}
		req, rerr := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://daemon.invalid/", http.NoBody)
		require.NoError(t, rerr)
		resp, derr := hc.Do(req)
		if derr != nil {
			return derr
		}
		_ = resp.Body.Close()
		return nil
	}

	require.NoError(t, get(edge), "the Edge reaches the handler")
	require.Len(t, reached, 1)

	require.Error(t, get(gateway), "another peer of the trust domain is refused")
	assert.Len(t, reached, 1, "the refused peer reached no handler")
}
