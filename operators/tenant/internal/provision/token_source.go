// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package provision holds the operator's client of the daemon
// DaemonOperatorService (DaemonClient) and the token source it uses.
//
// This file holds the TokenSource contract. The operator mints a Zitadel
// service-account token through the OAuth2 client_credentials grant and
// carries it as Bearer metadata on each daemon call.
package provision

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// TokenSource provides the Bearer token that DaemonClient sends on each
// daemon call. Keeping the contract narrow lets tests
// inject a static token without requiring a live Zitadel instance.
type TokenSource interface {
	// FetchToken returns a Bearer token string. The audience parameter is
	// passed through for implementations that need to scope the token (e.g.,
	// SPIFFE JWT-SVIDs). Zitadel client_credentials implementations may
	// ignore audience and always return the same access token.
	FetchToken(ctx context.Context, audience string) (string, error)
}

// OAuth2TokenSource adapts a golang.org/x/oauth2.TokenSource into the
// TokenSource interface. The audience parameter is ignored; Zitadel
// client_credentials tokens are scoped by the configured scopes, not per-call
// audiences. Safe for concurrent use (the underlying oauth2.TokenSource caches
// and refreshes tokens transparently before expiry).
type OAuth2TokenSource struct {
	Source oauth2.TokenSource
}

// FetchToken implements TokenSource.
func (o *OAuth2TokenSource) FetchToken(_ context.Context, _ string) (string, error) {
	tok, err := o.Source.Token()
	if err != nil {
		return "", fmt.Errorf("OAuth2TokenSource: %w", err)
	}
	return tok.AccessToken, nil
}
