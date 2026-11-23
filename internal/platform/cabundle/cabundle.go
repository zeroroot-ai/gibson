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

// Normalize returns the CA certificates of pemData as new PEM, and nothing else.
//
// The input must hold CERTIFICATE blocks and white space only. pem.Decode skips
// text before and between blocks, so a secret such as "token\n-----BEGIN ..."
// would pass a plain decode and its text would reach the pod. Normalize refuses
// any other byte outside the blocks, refuses a block of another type, and
// refuses a certificate that is not a CA (BasicConstraints CA true). The output
// is built from the parsed certificates, so it holds no header and no text that
// the input had. The error never holds the content.
func Normalize(pemData []byte) ([]byte, error) {
	rest := pemData
	var out []byte
	for {
		idx := bytes.Index(rest, []byte("-----BEGIN "))
		if idx < 0 {
			if len(bytes.TrimSpace(rest)) > 0 {
				return nil, errors.New("the bundle holds text that is not PEM outside the certificates")
			}
			break
		}
		if len(bytes.TrimSpace(rest[:idx])) > 0 {
			return nil, errors.New("the bundle holds text that is not PEM outside the certificates")
		}
		block, after := pem.Decode(rest[idx:])
		if block == nil {
			return nil, errors.New("the bundle holds a PEM block that does not decode")
		}
		// pem.Decode skips a block that is malformed and returns the next one.
		// The block that it returned must start where the text starts, so the
		// skipped text cannot hide before a certificate.
		consumed := rest[idx : len(rest)-len(after)]
		if !bytes.HasPrefix(consumed, []byte("-----BEGIN "+block.Type+"-----")) {
			return nil, errors.New("the bundle holds text that is not PEM outside the certificates")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the bundle holds a %q block, and only CERTIFICATE blocks are allowed", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("a certificate of the bundle does not parse")
		}
		if !isTrustAnchor(cert) {
			return nil, errors.New("a certificate of the bundle is neither a CA certificate nor self-signed")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		rest = after
	}
	if len(out) == 0 {
		return nil, errors.New("the bundle holds no PEM certificate")
	}
	return out, nil
}
