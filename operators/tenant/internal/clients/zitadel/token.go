// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"errors"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// apiScopes are the scopes of the operator's Zitadel API token. The
// zitadel:aud scope puts Zitadel's own project in the token audience. Without
// it the Management and v2 APIs answer 401.
var apiScopes = []string{"openid", "urn:zitadel:iam:org:project:id:zitadel:aud"}

// platformScopes are the scopes of the token the operator sends to the
// dashboard's provisioning API. The gibson-platform:aud scope puts
// gibson-platform in the token audience, which Envoy jwt_authn requires.
var platformScopes = []string{"openid", "urn:zitadel:iam:org:project:id:gibson-platform:aud"}

// tokenTimeout bounds one token request.
const tokenTimeout = 30 * time.Second

// TokenSources are the two Bearer token sources of the tenant-operator. Both
// are client_credentials grants for the operator's own machine user (the
// gibson-tenant-operator OIDCClient), cached and refreshed before expiry. The
// operator therefore holds only the Zitadel roles that user declares, never
// the owner credentials.
type TokenSources struct {
	// API authenticates calls to Zitadel's own Management and v2 APIs.
	API oauth2.TokenSource
	// Platform authenticates calls to the dashboard's provisioning API.
	Platform oauth2.TokenSource
}

// NewTokenSources builds both token sources for ep.
//
// Every token request goes to the in-cluster Service and claims the public
// host with the instance header, both from ep (ADR-0092). No request builds a
// URL from an issuer.
func NewTokenSources(ctx context.Context, ep zitadelconn.Endpoint, clientID, clientSecret string) (TokenSources, error) {
	if clientID == "" || clientSecret == "" {
		return TokenSources{}, errors.New("zitadel: the operator's client ID and client secret are both required")
	}
	if ep.IsZero() {
		return TokenSources{}, errors.New("zitadel: the endpoint is not set; build it with zitadelconn.New or zitadelconn.FromEnv")
	}
	hctx := context.WithValue(ctx, oauth2.HTTPClient, ep.HTTPClient(tokenTimeout))
	source := func(scopes []string) oauth2.TokenSource {
		cfg := clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     ep.TokenURL(),
			Scopes:       scopes,
		}
		return oauth2.ReuseTokenSource(nil, cfg.TokenSource(hctx))
	}
	return TokenSources{API: source(apiScopes), Platform: source(platformScopes)}, nil
}
