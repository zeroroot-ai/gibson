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

// Check reports an error when pemData is not a bundle of certificates. It
// refuses a block of another type, so a private key in the secret is never
// copied to the gateway. The error never holds the content.
func Check(pemData []byte) error {
	rest := pemData
	certs := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("the bundle holds a %q block, and only CERTIFICATE blocks are allowed", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("a certificate of the bundle does not parse: %w", err)
		}
		certs++
	}
	if certs == 0 {
		return errors.New("the bundle holds no PEM certificate")
	}
	if len(rest) > 0 {
		for _, b := range rest {
			if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
				return errors.New("the bundle holds text that is not PEM after the last certificate")
			}
		}
	}
	return nil
}
