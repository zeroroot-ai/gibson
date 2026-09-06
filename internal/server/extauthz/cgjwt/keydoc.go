// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Per-kid key resolution — the single key-resolution path (ADR-0045).
//
// ADR-0045 collapses CG-JWT verification to "one verification path keyed by
// kid: the daemon's own kid → daemon-minted, task-scoped dispatch tokens; a
// component kid → component-signed client tokens. Same ext-authz fetch-by-kid
// + FGA for both." Both verifiers in this package therefore resolve their
// verifying key through the functions below, against the daemon's
// GET {KeysBaseURL}/{kid} endpoint (internal/server/daemon/capabilitygrant_keys.go).
//
// There is deliberately no JWKS-wide fetch: the daemon publishes no key-set
// document, and ext-authz never enumerates the registered component keys.

// maxKeyDocBytes bounds the response body read from the key endpoint. The
// documents are a single JWK plus three short strings; anything larger is a
// misconfigured upstream, not a key.
const maxKeyDocBytes = 1 << 16

// keyDoc is the wire shape served by the daemon's per-kid key endpoint. It is
// a JWKS superset: `keys` carries the JWK itself, and a component key document
// additionally carries the daemon-asserted principal, tenant and status. The
// daemon's own dispatch key is served as a bare document — `keys` only — which
// is how the two are told apart (see keyDoc.isBare).
type keyDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
	} `json:"keys"`
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
	Status    string `json:"status"`
}

// isBare reports whether the document carries no component binding — the shape
// the daemon serves for its own dispatch signing kid. A component key document
// always carries principal+tenant+status.
func (d keyDoc) isBare() bool {
	return d.Principal == "" && d.Tenant == "" && d.Status == ""
}

// fetchKeyDoc GETs the key document for kid from the daemon.
//
// kid comes from an unverified JWT header, so it is attacker-controlled and is
// path-escaped before it is joined onto the base URL. Without that, a kid such
// as "../../admin" would address a different daemon endpoint than the key
// endpoint this verifier is configured for.
func fetchKeyDoc(ctx context.Context, client *http.Client, baseURL, kid string) (keyDoc, error) {
	target := baseURL + "/" + url.PathEscape(kid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return keyDoc{}, fmt.Errorf("build key request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return keyDoc{}, fmt.Errorf("key fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return keyDoc{}, fmt.Errorf("key fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyDocBytes))
	if err != nil {
		return keyDoc{}, fmt.Errorf("read key document: %w", err)
	}
	var doc keyDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return keyDoc{}, fmt.Errorf("key document decode: %w", err)
	}
	return doc, nil
}

// ed25519FromKeyDoc extracts the Ed25519 key matching kid (or the sole key).
func ed25519FromKeyDoc(doc keyDoc, kid string) (ed25519.PublicKey, error) {
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		if k.Kid != "" && k.Kid != kid {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("kid %q: bad x: %w", kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("kid %q: ed25519 key length %d", kid, len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("key document for kid %q has no usable Ed25519 key", kid)
}
