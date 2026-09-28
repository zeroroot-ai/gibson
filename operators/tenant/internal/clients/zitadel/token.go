// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// tokenScopes are the scopes of the operator's Zitadel API token. The
// zitadel:aud scope puts Zitadel's own project in the token audience. Without
// it the Management and v2 APIs answer 401.
var tokenScopes = []string{"openid", "urn:zitadel:iam:org:project:id:zitadel:aud"}

// tokenTimeout bounds one token request.
const tokenTimeout = 30 * time.Second

// TokenSource returns the Bearer tokens this client sends. It is a
// client_credentials grant for the tenant-operator's own machine user (the
// gibson-tenant-operator OIDCClient), cached and refreshed before expiry. The
// operator therefore holds only the Zitadel roles that user declares, never
// the owner credentials.
//
// The token request goes to the in-cluster Service (zitadelURL) and claims
// the public host (externalDomain) with the instance header (ADR-0092).
func TokenSource(ctx context.Context, zitadelURL, externalDomain, clientID, clientSecret string) (oauth2.TokenSource, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("zitadel: the operator's client ID and client secret are both required")
	}
	ep, err := zitadelconn.New(zitadelURL, externalDomain)
	if err != nil {
		return nil, fmt.Errorf("zitadel: token endpoint: %w", err)
	}
	cfg := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ep.TokenURL(),
		Scopes:       tokenScopes,
	}
	hctx := context.WithValue(ctx, oauth2.HTTPClient, ep.HTTPClient(tokenTimeout))
	return oauth2.ReuseTokenSource(nil, cfg.TokenSource(hctx)), nil
}
