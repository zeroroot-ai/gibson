// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// The metrics port carries no API (charts#515): it answers GET /metrics and
// refuses every other path, so a network rule can admit the scraper to it.
func TestMetricsMuxServesOnlyMetrics(t *testing.T) {
	h := metricsMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/metrics", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusNotFound},
		{http.MethodGet, "/readyz", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, http.NoBody))
		if rec.Code != c.want {
			t.Errorf("%s %s: got %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}

// The series of the D9 alert reaches the metrics port: the counter is on the
// default registry that the metrics listener serves.
func TestMetricsMuxServesTheReplayStoreCounter(t *testing.T) {
	h := metricsMux(observability.DefaultPrometheusHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: got %d", rec.Code)
	}
	if !strings.Contains(string(body), "extauthz_cgjwt_component_replay_state_unavailable_total") {
		t.Fatal("the replay-store counter of the D9 alert is not on the metrics port")
	}
}

// startMetricsListener starts on valid material and refuses a directory
// with none, so main exits instead of running with no metrics port.
func TestStartMetricsListener(t *testing.T) {
	dir := t.TempDir()
	writeMetricsMaterial(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.DiscardHandler)

	errC, err := startMetricsListener(ctx, log, "127.0.0.1:0", dir)
	if err != nil {
		t.Fatalf("start on valid material: %v", err)
	}
	cancel()
	select {
	case err := <-errC:
		t.Fatalf("a clean shutdown must send no error, got %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	if _, err := startMetricsListener(context.Background(), log, "127.0.0.1:0", t.TempDir()); err == nil {
		t.Fatal("a directory with no material must refuse the start")
	}
}

// writeMetricsMaterial writes a CA and a server leaf as tls.crt, tls.key and
// ca.crt, the layout of the cert-manager Secret.
func writeMetricsMaterial(t *testing.T, dir string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("leaf key DER: %v", err)
	}
	for name, block := range map[string]*pem.Block{
		"ca.crt":  {Type: "CERTIFICATE", Bytes: caDER},
		"tls.crt": {Type: "CERTIFICATE", Bytes: leafDER},
		"tls.key": {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}
