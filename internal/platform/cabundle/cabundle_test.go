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

func leafPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Text before or between the blocks is skipped by pem.Decode. Normalize refuses
// it, so a token in the secret never reaches the pod.
func TestNormalize_RefusesTextOutsideTheBlocks(t *testing.T) {
	c := certPEM(t, "c")
	cases := map[string][]byte{
		"text before":                   append([]byte("ghp_secrettoken\n"), c...),
		"text between":                  append(append(append([]byte{}, c...), []byte("ghp_secrettoken\n")...), certPEM(t, "d")...),
		"text after":                    append(append([]byte{}, c...), []byte("ghp_secrettoken")...),
		"a leaf that another CA signed": leafSignedByAnotherCA(t),
	}
	for name, data := range cases {
		out, err := Normalize(data)
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
		if err != nil && strings.Contains(err.Error(), "ghp_secrettoken") {
			t.Errorf("%s: the error holds the content", name)
		}
		if len(out) != 0 {
			t.Errorf("%s: output = %q", name, out)
		}
	}
}

// The output is built from the parsed certificates: headers of the input are
// gone, and white space between the blocks is not kept.
func TestNormalize_ReEncodesTheCertificates(t *testing.T) {
	c1, c2 := certPEM(t, "one"), certPEM(t, "two")
	in := append(append(append([]byte("\n  "), c1...), []byte("\n\n   ")...), c2...)
	out, err := Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(c1)+string(c2) {
		t.Errorf("output = %q", out)
	}
}

// leafSignedByAnotherCA is a server certificate with no CA flag that a CA
// signed. It is not a trust anchor.
func leafSignedByAnotherCA(t *testing.T) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "issuer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func intermediatePEM(t *testing.T) []byte {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A bundle of a model provider or an outside agent worked with a self-signed
// server certificate that has no CA flag, with a root that has no
// BasicConstraints and with an intermediate. All three stay accepted. A leaf that
// another CA signed is refused.
func TestNormalize_AcceptsTheAnchorsThatTenantsUse(t *testing.T) {
	for name, data := range map[string][]byte{
		"a self-signed leaf": leafPEM(t),
		"an intermediate":    intermediatePEM(t),
		"a CA":               certPEM(t, "ca"),
	} {
		if _, err := Normalize(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Normalize(leafSignedByAnotherCA(t)); err == nil {
		t.Error("a leaf that another CA signed must be refused")
	}
}

// A BEGIN line with no END line is skipped by pem.Decode, and the next block is
// returned. Normalize refuses the skipped text.
func TestNormalize_RefusesAMalformedBlockBeforeACertificate(t *testing.T) {
	in := append([]byte("-----BEGIN junk\nghp_secrettoken\n"), certPEM(t, "c")...)
	out, err := Normalize(in)
	if err == nil {
		t.Fatal("want an error")
	}
	if len(out) != 0 || strings.Contains(err.Error(), "ghp_secrettoken") {
		t.Errorf("out = %q, err = %v", out, err)
	}
}
