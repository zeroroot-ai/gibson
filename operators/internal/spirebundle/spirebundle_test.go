// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package spirebundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCertDER is a self-signed CA certificate, the shape of a SPIRE root.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spire-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

// ToPEM keeps each x509-svid certificate and drops the jwt-svid keys.
func TestToPEM(t *testing.T) {
	der := testCertDER(t)
	raw := `{"keys":[` +
		`{"use":"x509-svid","kty":"EC","x5c":["` + base64.StdEncoding.EncodeToString(der) + `"]},` +
		`{"use":"jwt-svid","kty":"EC","kid":"k1"}]}`
	got, err := ToPEM(raw)
	if err != nil {
		t.Fatalf("ToPEM: %v", err)
	}
	block, rest := pem.Decode([]byte(got))
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, der) {
		t.Fatalf("PEM = %q, want the one certificate", got)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Errorf("PEM has more than the one certificate: %q", rest)
	}
}

// The URL-safe base64 form decodes to the same certificate.
func TestToPEM_URLBase64(t *testing.T) {
	der := testCertDER(t)
	raw := `{"keys":[{"use":"x509-svid","x5c":["` + base64.URLEncoding.EncodeToString(der) + `"]}]}`
	got, err := ToPEM(raw)
	if err != nil || !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("ToPEM = %q, %v", got, err)
	}
}

// A bundle with no x509-svid entry gives an empty PEM and no error. The
// caller decides whether that is fatal.
func TestToPEM_NoX509Entry(t *testing.T) {
	got, err := ToPEM(`{"keys":[{"use":"jwt-svid","kid":"k1"}]}`)
	if err != nil || got != "" {
		t.Fatalf("ToPEM = %q, %v, want empty and no error", got, err)
	}
}

// Each malformed input is refused with its cause.
func TestToPEM_Errors(t *testing.T) {
	for name, c := range map[string]struct{ raw, want string }{
		"not json":        {`{`, "parse JWKS json"},
		"not base64":      {`{"keys":[{"use":"x509-svid","x5c":["%%%"]}]}`, "decode x5c base64"},
		"not certificate": {`{"keys":[{"use":"x509-svid","x5c":["` + base64.StdEncoding.EncodeToString([]byte("x")) + `"]}]}`, "parse x5c DER"},
	} {
		if _, err := ToPEM(c.raw); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
