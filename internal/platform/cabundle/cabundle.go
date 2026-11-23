// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package cabundle checks the private CA bundle of a tenant-supplied backend
// (gibson#1403). A tenant stores the PEM bundle as a tenant secret, and the
// record of a model provider or of an outside agent names that secret in the
// field ca_bundle_secret. The daemon checks the content when the record is
// saved. The tenant operator copies the content into the credential Secret of
// the backend under the key Key, and the gateway verifies the server
// certificate of the backend against it.
package cabundle

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key is the key of the CA bundle in the Secret that the gateway reads. It is the
// default key of the field caCertificateRefs of the policy tls of a backend.
const Key = "ca.crt"

// Field is the name of the field that holds the name of the tenant secret with
// the bundle. A provider record keeps it as a credential field, as it keeps
// base_url. An outside agent record keeps it in a column.
const Field = "ca_bundle_secret"

// Check reports an error when pemData is not a bundle of CA certificates. It
// is Normalize, and it drops the result. The error never holds the content.
func Check(pemData []byte) error {
	_, err := Normalize(pemData)
	return err
}

// isTrustAnchor reports whether a certificate can be a trust anchor: a CA with
// valid BasicConstraints, or a self-signed certificate. A self-signed server
// certificate (a self-hosted endpoint) and a v1 root with no BasicConstraints
// are anchors that tenants use. A leaf that another CA signed is not.
func isTrustAnchor(c *x509.Certificate) bool {
	if c.IsCA && c.BasicConstraintsValid {
		return true
	}
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// Normalize returns the trust anchors of pemData as new PEM, and nothing else.
//
// A bundle of a real install holds more than certificates: the Mozilla bundle
// has a name line and a row of "=" before each block, and a full chain has a
// server certificate beside its CAs. So Normalize accepts any text outside the
// blocks, and it drops a certificate that is not a trust anchor. None of it
// reaches the output. The output is built from the parsed certificates, so it
// holds no header, no comment and no text that the input had.
//
// A block of another type (a private key, for example) refuses the whole
// bundle, as does a certificate that does not parse, and a bundle with no
// anchor at all. The error never holds the content.
func Normalize(pemData []byte) ([]byte, error) {
	rest := pemData
	var out []byte
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the bundle holds a %q block, and only CERTIFICATE blocks are allowed", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("a certificate of the bundle does not parse")
		}
		if !isTrustAnchor(cert) {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(out) == 0 {
		return nil, errors.New("the bundle holds no CA certificate and no self-signed certificate")
	}
	return out, nil
}
