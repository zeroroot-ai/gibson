// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package entitlements

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
)

// TestNewGRPCProvider_RefusesAnEndpointWithNoBillingIdentity: with an
// endpoint and no SPIFFE ID of the billing service, the client refuses to
// start. It does not fall back to any workload of the trust domain.
func TestNewGRPCProvider_RefusesAnEndpointWithNoBillingIdentity(t *testing.T) {
	_, err := NewGRPCProvider(GRPCProviderOptions{Endpoint: "billing:9443"})
	if !errors.Is(err, ErrBillingServiceSVIDRequired) {
		t.Fatalf("err = %v, want ErrBillingServiceSVIDRequired", err)
	}
	_, err = NewGRPCProvider(GRPCProviderOptions{Endpoint: "billing:9443", BillingServiceSVID: "not-a-spiffe-id"})
	if err == nil {
		t.Fatal("an invalid SPIFFE ID must be refused")
	}
}

// TestBillingClientTLSConfig_OnlyTheBillingIdentityCompletesTheHandshake:
// one CA issues every SVID of the trust domain. A server with the SVID of
// the billing service completes the handshake. A server with a different
// SVID of the same trust domain fails it.
func TestBillingClientTLSConfig_OnlyTheBillingIdentityCompletesTheHandshake(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := newIdentityTestCA(t)
	billing := spiffeid.RequireFromPath(td, "/platform/billing")
	other := spiffeid.RequireFromPath(td, "/platform/other")
	daemon := spiffeid.RequireFromPath(td, "/platform/daemon")

	client := ca.source(t, daemon)
	cfg := billingClientTLSConfig(client, client, billing)

	if err := handshake(t, cfg, ca.source(t, billing), daemon); err != nil {
		t.Fatalf("the billing service must complete the handshake: %v", err)
	}
	if err := handshake(t, cfg, ca.source(t, other), daemon); err == nil {
		t.Fatal("a different workload of the trust domain completed the handshake")
	}
}

// handshake runs one TLS handshake between the client config and a server
// that presents the SVID of server and accepts the client id.
func handshake(t *testing.T, client *tls.Config, server *identitySource, clientID spiffeid.ID) error {
	t.Helper()
	serverCfg := tlsconfig.MTLSServerConfig(server, server, tlsconfig.AuthorizeID(clientID))
	cConn, sConn := net.Pipe()
	defer func() { _ = cConn.Close() }()
	defer func() { _ = sConn.Close() }()
	_ = cConn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = sConn.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv := tls.Server(sConn, serverCfg)
		_ = srv.Handshake()
		_ = srv.Close()
	}()
	cli := tls.Client(cConn, client)
	err := cli.Handshake()
	_ = cli.Close()
	<-done
	return err
}

// identityTestCA issues X509-SVIDs for the handshake test.
type identityTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newIdentityTestCA(t *testing.T) *identityTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &identityTestCA{cert: cert, key: key}
}

// source issues an SVID for id and trusts this CA.
func (ca *identityTestCA) source(t *testing.T, id spiffeid.ID) *identitySource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		t.Fatalf("parse %s: %v", id, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign leaf for %s: %v", id, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf for %s: %v", id, err)
	}
	return &identitySource{
		svid:   &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key},
		bundle: x509bundle.FromX509Authorities(id.TrustDomain(), []*x509.Certificate{ca.cert}),
	}
}

// identitySource is a fixed SVID and trust bundle. It satisfies the two
// source interfaces that *workloadapi.X509Source satisfies in production.
type identitySource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s *identitySource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func (s *identitySource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}
