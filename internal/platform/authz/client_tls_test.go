// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for the FGA client transport: TLSEnabled makes the client dial TLS
// and trust only the configured CA, TLSEnabled false adds no TLS settings,
// and TLSEnabled without a usable CA fails at construction.
package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	tlsTestStoreID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	tlsTestModelID = "01ARZ3NDEKTSV4RRFFQ69G5FBV"
)

// allowAllHandler answers every FGA call with an allowed Check response.
func allowAllHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	})
}

// writeServerCA writes the certificate of a TLS test server as a PEM file.
func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

// writeOtherCA writes a new self-signed CA that signed no test server.
// Every httptest TLS server uses the same built-in certificate, so a second
// server is not a different CA.
func writeOtherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "other test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "other-ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

func checkOnce(t *testing.T, cfg FgaConfig) error {
	t.Helper()
	a, err := NewFgaAuthorizer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFgaAuthorizer: %v", err)
	}
	_, err = a.Check(context.Background(), "user:_system", "platform_operator", "system_tenant:_system")
	return err
}

func TestFgaTransport_TLSOnUsesConfiguredCA(t *testing.T) {
	srv := httptest.NewTLSServer(allowAllHandler())
	defer srv.Close()
	caFile := writeServerCA(t, srv)

	cfg := FgaConfig{
		Endpoint:   strings.TrimPrefix(srv.URL, "https://"),
		StoreID:    tlsTestStoreID,
		ModelID:    tlsTestModelID,
		TLSEnabled: true,
		TLSCAFile:  caFile,
	}
	endpoint, transport, err := fgaTransport(cfg)
	if err != nil {
		t.Fatalf("fgaTransport: %v", err)
	}
	if !strings.HasPrefix(endpoint, "https://") {
		t.Errorf("endpoint = %q, want an https endpoint", endpoint)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("TLS on: the transport has no TLS config with the configured CA")
	}

	if err := checkOnce(t, cfg); err != nil {
		t.Fatalf("Check over TLS with the server CA: %v", err)
	}
}

func TestFgaTransport_TLSOnRejectsServerFromOtherCA(t *testing.T) {
	srv := httptest.NewTLSServer(allowAllHandler())
	defer srv.Close()

	err := checkOnce(t, FgaConfig{
		Endpoint:   srv.URL,
		StoreID:    tlsTestStoreID,
		ModelID:    tlsTestModelID,
		TLSEnabled: true,
		TLSCAFile:  writeOtherCA(t),
	})
	if err == nil {
		t.Fatal("Check succeeded against a server that the configured CA did not sign")
	}
}

func TestFgaTransport_TLSOffHasNoTLSConfig(t *testing.T) {
	srv := httptest.NewServer(allowAllHandler())
	defer srv.Close()

	cfg := FgaConfig{
		Endpoint: strings.TrimPrefix(srv.URL, "http://"),
		StoreID:  tlsTestStoreID,
		ModelID:  tlsTestModelID,
	}
	endpoint, transport, err := fgaTransport(cfg)
	if err != nil {
		t.Fatalf("fgaTransport: %v", err)
	}
	if !strings.HasPrefix(endpoint, "http://") {
		t.Errorf("endpoint = %q, want an http endpoint", endpoint)
	}
	if transport.TLSClientConfig != nil {
		t.Error("TLS off: the transport carries a TLS config")
	}
	if err := checkOnce(t, cfg); err != nil {
		t.Fatalf("Check over plain http: %v", err)
	}
}

func TestNewFgaAuthorizer_TLSOnFailsWithoutUsableCA(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	cases := map[string]FgaConfig{
		"no CA file":      {Endpoint: "https://fga:8080"},
		"missing CA file": {Endpoint: "https://fga:8080", TLSCAFile: filepath.Join(t.TempDir(), "absent.crt")},
		"CA file not PEM": {Endpoint: "https://fga:8080", TLSCAFile: notPEM},
		"http endpoint":   {Endpoint: "http://fga:8080", TLSCAFile: notPEM},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.StoreID = tlsTestStoreID
			cfg.ModelID = tlsTestModelID
			cfg.TLSEnabled = true
			a, err := NewFgaAuthorizer(context.Background(), cfg)
			if err == nil {
				t.Fatalf("NewFgaAuthorizer returned %T and no error", a)
			}
			if !IsInvalidArgument(err) {
				t.Errorf("error = %v, want an invalid argument error", err)
			}
		})
	}
}
