// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The client trusts the CA of the file. A gateway that another CA signed is not
// trusted.
func TestModelGatewayHTTPClient_TrustsOnlyTheGivenCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	dir := t.TempDir()
	good := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(good, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := modelGatewayHTTPClient(good)
	if err != nil {
		t.Fatalf("modelGatewayHTTPClient: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("a gateway of the trusted CA was refused: %v", err)
	}
	_ = resp.Body.Close()

	// A bundle of a different CA does not trust this server.
	otherFile := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(otherFile, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := modelGatewayHTTPClient(otherFile)
	if err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if resp, err := c2.Do(req2); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a gateway that another CA signed was trusted")
	}
}

func TestModelGatewayHTTPClient_Refusals(t *testing.T) {
	if _, err := modelGatewayHTTPClient(""); err == nil {
		t.Error("no CA file was accepted")
	}
	if _, err := modelGatewayHTTPClient(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("a missing file was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := modelGatewayHTTPClient(bad); err == nil {
		t.Error("a file with no certificate was accepted")
	}
}

// selfSignedPEM returns a self-signed CA certificate that signed nothing here.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "another CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestModelGatewayInfoFromEnv(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvModelGatewayURL, "https://gw.example")
	t.Setenv(EnvModelGatewayCAFile, ca)
	info, err := modelGatewayInfoFromEnv()
	if err != nil || info.URL != "https://gw.example" || info.CAPEM == "" {
		t.Fatalf("info = %+v, %v", info, err)
	}
	t.Setenv(EnvModelGatewayURL, "")
	if _, err := modelGatewayInfoFromEnv(); err == nil {
		t.Error("no URL was accepted")
	}
	t.Setenv(EnvModelGatewayURL, "https://gw.example")
	t.Setenv(EnvModelGatewayCAFile, filepath.Join(dir, "missing.pem"))
	if _, err := modelGatewayInfoFromEnv(); err == nil {
		t.Error("a missing CA file was accepted")
	}
}
