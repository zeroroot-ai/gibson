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
		"empty":                {},
		"plain text":           []byte("hello"),
		"a private key":        key,
		"a certificate+a key":  append(certPEM(t, "c"), key...),
		"a broken certificate": bad,
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
// BasicConstraints and with an intermediate. All stay accepted.
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
}

// The Mozilla bundle (certifi cacert.pem) has a name line and a row of "="
// before each block. The text is accepted and never reaches the output.
func TestNormalize_AcceptsTheShapeOfTheMozillaBundle(t *testing.T) {
	a, b := certPEM(t, "a"), certPEM(t, "b")
	in := "# Issuer: CN=A\n# Subject: CN=A\n# Label: \"A\"\n# MD5 Fingerprint: 00:11\n" +
		"# SHA256 Fingerprint: ghp_secrettoken\n" + string(a) +
		"\n# Issuer: CN=B\n=========\n" + string(b) + "\ntrailing ghp_secrettoken\n"
	out, err := Normalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(a)+string(b) {
		t.Errorf("output = %q", out)
	}
}

// A full chain holds the server certificate beside its CAs. Only the anchors come
// out. A bundle with only a leaf that another CA signed has no anchor and is refused.
func TestNormalize_DropsACertificateThatIsNoAnchor(t *testing.T) {
	leaf := leafSignedByAnotherCA(t)
	inter := intermediatePEM(t)
	root := certPEM(t, "root")
	out, err := Normalize(append(append(append([]byte{}, leaf...), inter...), root...))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(inter)+string(root) {
		t.Errorf("only the anchors must come out: %q", out)
	}
	if _, err := Normalize(leaf); err == nil {
		t.Error("a bundle with no anchor must be refused")
	}
}

// A block that is not a certificate refuses the bundle, with or without text
// around it. A malformed BEGIN line before a certificate does not leak.
func TestNormalize_RefusesABlockThatIsNotACertificate(t *testing.T) {
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-bytes")})
	if _, err := Normalize(append(certPEM(t, "c"), key...)); err == nil {
		t.Error("a key block must refuse the bundle")
	}
	in := append([]byte("-----BEGIN junk\nghp_secrettoken\n"), certPEM(t, "c")...)
	out, err := Normalize(in)
	if err != nil {
		t.Fatalf("a malformed line before a certificate: %v", err)
	}
	if strings.Contains(string(out), "ghp_secrettoken") {
		t.Error("the text reached the output")
	}
}
