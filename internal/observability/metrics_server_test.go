package observability

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewMetricsServer_RejectsMissingMaterial covers the fail-fast contract
// from Spec security-hardening R20: any missing TLS material aborts startup.
func TestNewMetricsServer_RejectsMissingMaterial(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mutate  func(*MetricsServerConfig)
		wantSub string
	}{
		{
			name:    "nil handler",
			mutate:  func(c *MetricsServerConfig) { c.Handler = nil },
			wantSub: "handler is required",
		},
		{
			name:    "missing cert path",
			mutate:  func(c *MetricsServerConfig) { c.CertPath = "" },
			wantSub: "TLS material paths are required",
		},
		{
			name:    "missing key path",
			mutate:  func(c *MetricsServerConfig) { c.KeyPath = "" },
			wantSub: "TLS material paths are required",
		},
		{
			name:    "missing ca path",
			mutate:  func(c *MetricsServerConfig) { c.ClientCAPath = "" },
			wantSub: "TLS material paths are required",
		},
		{
			name: "unreadable cert",
			mutate: func(c *MetricsServerConfig) {
				c.CertPath = "/no/such/path/tls.crt"
			},
			wantSub: "load server cert/key",
		},
		{
			name: "garbage CA bundle",
			mutate: func(c *MetricsServerConfig) {
				c.ClientCAPath = mustWriteTempFile(t, []byte("not a PEM"))
			},
			wantSub: "not valid PEM",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca, _, _, _ := mustGenerateCA(t)
			caPath, certPath, keyPath := mustWriteServerMaterial(t, ca)

			cfg := MetricsServerConfig{
				Addr:         "127.0.0.1:0",
				CertPath:     certPath,
				KeyPath:      keyPath,
				ClientCAPath: caPath,
				Handler:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			}
			tc.mutate(&cfg)

			srv, err := NewMetricsServer(cfg)
			if err == nil {
				t.Fatalf("expected error, got server=%v", srv)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

// TestMetricsServer_ServesOverMTLS spins the listener on a random port,
// scrapes it with a client cert signed by the trusted CA, and verifies
// that:
//   - a properly-authenticated client gets the handler payload, and
//   - a client without a cert is rejected at the TLS handshake.
//
// Together those exercise the RequireAndVerifyClientCert path that
// Spec R20 mandates.
func TestMetricsServer_ServesOverMTLS(t *testing.T) {
	t.Parallel()

	caCert, caKey, caPEM, _ := mustGenerateCA(t)
	caPath := mustWriteTempFile(t, caPEM)
	certPath, keyPath := mustWriteServerLeaf(t, caCert, caKey)

	const body = "metric_value 1\n"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})

	srv, err := NewMetricsServer(MetricsServerConfig{
		Addr:         "127.0.0.1:0",
		CertPath:     certPath,
		KeyPath:      keyPath,
		ClientCAPath: caPath,
		Handler:      handler,
	})
	if err != nil {
		t.Fatalf("NewMetricsServer: %v", err)
	}

	// Pre-bind so we can discover the chosen port and feed it back to
	// the http.Server before Serve runs ListenAndServeTLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv.srv.Addr = addr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var serveErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveErr = srv.Serve(ctx)
	}()

	// Wait briefly for the listener to come up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, dErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dErr == nil {
			_ = conn.Close()
			break
		}
	}

	clientCertPEM, clientKeyPEM := mustGenerateClientLeaf(t, caCert, caKey)
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Authenticated client must succeed.
	authedClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientCert},
				ServerName:   "localhost",
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
	resp, err := authedClient.Get("https://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("authed scrape: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(gotBody) != body {
		t.Fatalf("body mismatch: %q vs %q", string(gotBody), body)
	}

	// Anonymous client must fail at the TLS handshake.
	anonClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS13,
			},
		},
	}
	if _, err := anonClient.Get("https://" + addr + "/metrics"); err == nil {
		t.Fatalf("expected handshake failure for anonymous client, got nil")
	}

	cancel()
	wg.Wait()
	if serveErr != nil {
		t.Fatalf("Serve returned %v (want nil after ctx cancel)", serveErr)
	}
}

// TestMetricsServer_Serve_NilReceiver ensures the helper guard fires.
func TestMetricsServer_Serve_NilReceiver(t *testing.T) {
	t.Parallel()
	var s *MetricsServer
	err := s.Serve(context.Background())
	if err == nil {
		t.Fatalf("expected error from nil receiver")
	}
	if !errors.Is(err, errors.New("metrics: server not initialised")) &&
		!strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------- test helpers ----------

func mustGenerateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("ca key marshal: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return cert, key, certPEM, keyPEM
}

func mustGenerateLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, isClient bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if isClient {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf create: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("leaf key marshal: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func mustWriteServerLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM := mustGenerateLeaf(t, ca, caKey, false)
	return mustWriteTempFile(t, certPEM), mustWriteTempFile(t, keyPEM)
}

func mustWriteServerMaterial(t *testing.T, ca *x509.Certificate) (caPath, certPath, keyPath string) {
	t.Helper()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	caPath = mustWriteTempFile(t, caPEM)
	// We need a server leaf signed by `ca`; the helper above generates one
	// using a fresh CA each time, so pull a separate path for that flow:
	caCert, caKey, _, _ := mustGenerateCA(t)
	_ = caCert
	certPEM, keyPEM := mustGenerateLeaf(t, caCert, caKey, false)
	return caPath, mustWriteTempFile(t, certPEM), mustWriteTempFile(t, keyPEM)
}

func mustGenerateClientLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte) {
	t.Helper()
	return mustGenerateLeaf(t, ca, caKey, true)
}

func mustWriteTempFile(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "f.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}
