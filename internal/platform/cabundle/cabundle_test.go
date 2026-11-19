// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cabundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func certPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheck_AcceptsOneOrMoreCertificates(t *testing.T) {
	one := certPEM(t, "one")
	two := append(append([]byte{}, one...), certPEM(t, "two")...)
	for name, data := range map[string][]byte{"one": one, "two": two, "trailing newline": append(one, '\n')} {
		if err := Check(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheck_Refuses(t *testing.T) {
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-bytes")})
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	cases := map[string][]byte{
		"empty":                 {},
		"plain text":            []byte("hello"),
		"a private key":         key,
		"a certificate+a key":   append(certPEM(t, "c"), key...),
		"a broken certificate":  bad,
		"text after the bundle": append(certPEM(t, "c"), []byte("junk")...),
	}
	for name, data := range cases {
		err := Check(data)
		if err == nil {
			t.Errorf("%s: the bundle was accepted", name)
			continue
		}
		if len(data) > 0 && strings.Contains(err.Error(), "secret-key-bytes") {
			t.Errorf("%s: the error holds the content", name)
		}
	}
}
