// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// SPIFFE test fixtures: an in-memory CA that issues X509-SVIDs, and a source
// that satisfies both x509svid.Source and x509bundle.Source.
//
// These exist so the daemon-ward mTLS pin can be tested for what it actually
// claims. The distinction that matters is between "signed by a CA we trust"
// and "IS the daemon": every workload in the trust domain holds a valid SVID
// from the same CA, so a test that only swaps the CA proves transport
// security and says nothing about pinning. The fixture therefore lets one CA
// issue several identities.

// testCA is a self-signed CA that issues SVID leaf certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// issue mints an X509-SVID for id, signed by this CA.
func (ca *testCA) issue(t *testing.T, id spiffeid.ID) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		t.Fatalf("parse SPIFFE ID %q: %v", id, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: id.Path()},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
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
	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{cert},
		PrivateKey:   key,
	}
}

// staticSource is a fixed X509-SVID plus a fixed trust bundle. It implements
// x509svid.Source and x509bundle.Source, the two interfaces the daemon-ward
// mTLS client and its test peers consume — the same pair *workloadapi.X509Source
// satisfies in production.
type staticSource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

// newStaticSource issues an SVID for id from svidCA and trusts trustedCAs.
// Splitting the two is the point: a peer can hold a perfectly valid SVID from
// an authority the other side does not trust, or a valid SVID from an
// authority it does trust but under the wrong identity.
func newStaticSource(t *testing.T, svidCA *testCA, id spiffeid.ID, trustedCAs ...*testCA) *staticSource {
	t.Helper()
	authorities := make([]*x509.Certificate, 0, len(trustedCAs))
	for _, ca := range trustedCAs {
		authorities = append(authorities, ca.cert)
	}
	return &staticSource{
		svid:   svidCA.issue(t, id),
		bundle: x509bundle.FromX509Authorities(id.TrustDomain(), authorities),
	}
}

func (s *staticSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func (s *staticSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

func mustSPIFFEID(t *testing.T, s string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(s)
	if err != nil {
		t.Fatalf("parse SPIFFE ID %q: %v", s, err)
	}
	return id
}
