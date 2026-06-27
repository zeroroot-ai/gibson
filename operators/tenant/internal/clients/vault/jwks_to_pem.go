// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// jwks_to_pem.go: convert SPIRE k8s_configmap BundlePublisher JWKS output
// into a PEM bundle Vault accepts as `jwks_ca_pem`. Mirrors the awk/jq
// dance in deploy/helm/gibson-workloads/templates/auth/openbao-jwt-auth-init/job.yaml
// but in pure Go so the operator doesn't shell out at saga time.

package vault

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// jwksToPEM extracts x509-svid x5c entries from a SPIRE JWKS document and
// returns a concatenated PEM bundle suitable for Vault's `jwks_ca_pem`.
// Returns an empty string (no error) when the JWKS contains no x509-svid
// entries — the caller decides whether that's fatal.
//
// Input shape (SPIRE k8s_configmap BundlePublisher output, JWKS form):
//
//	{
//	  "keys": [
//	    {"use":"x509-svid","kty":"RSA","x5c":["MIID..."]},
//	    {"use":"jwt-svid","kty":"RSA","kid":"...","n":"...","e":"AQAB"}
//	  ]
//	}
func jwksToPEM(raw string) (string, error) {
	var bundle struct {
		Keys []struct {
			Use string   `json:"use"`
			X5C []string `json:"x5c"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &bundle); err != nil {
		return "", fmt.Errorf("parse JWKS json: %w", err)
	}
	var out []byte
	for _, k := range bundle.Keys {
		if k.Use != "x509-svid" {
			continue
		}
		for _, b64 := range k.X5C {
			// Each x5c entry is a base64-encoded DER cert.
			der, err := decodeStandardOrURLBase64(b64)
			if err != nil {
				return "", fmt.Errorf("decode x5c base64: %w", err)
			}
			if _, err := x509.ParseCertificate(der); err != nil {
				return "", fmt.Errorf("parse x5c DER: %w", err)
			}
			out = append(out, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: der,
			})...)
		}
	}
	return string(out), nil
}

// decodeStandardOrURLBase64 tries standard base64 first (the spec form for
// JWK x5c entries), then URL-safe as a fallback for tools that emit the
// alt encoding.
func decodeStandardOrURLBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
