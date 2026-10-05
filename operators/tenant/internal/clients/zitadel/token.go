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

// APIScopes are the scopes of the operator's Zitadel API token. The
// zitadel:aud scope puts Zitadel's own project in the token audience. Without
// it the Management and v2 APIs answer 401.
func APIScopes() []string {
	return []string{"openid", "urn:zitadel:iam:org:project:id:zitadel:aud"}
}

// PlatformScopes are the scopes of the token the operator sends to the
// dashboard's provisioning API. The gibson-platform:aud scope puts
// gibson-platform in the token audience, which Envoy jwt_authn requires.
func PlatformScopes() []string {
	return []string{"openid", "urn:zitadel:iam:org:project:id:gibson-platform:aud"}
}

// tokenTimeout bounds one token request.
const tokenTimeout = 30 * time.Second

// TokenSource returns the Bearer tokens this client sends. It is a
// client_credentials grant for the tenant-operator's own machine user (the
// gibson-tenant-operator OIDCClient), cached and refreshed before expiry. The
// operator therefore holds only the Zitadel roles that user declares, never
// the owner credentials.
//
// The token request goes to the in-cluster Service and claims the public host
// with the instance header, both from ep (ADR-0092). scopes select the
// audience: APIScopes for Zitadel's own APIs, PlatformScopes for the platform.
func TokenSource(ctx context.Context, ep zitadelconn.Endpoint, clientID, clientSecret string, scopes []string) (oauth2.TokenSource, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("zitadel: the operator's client ID and client secret are both required")
	}
	if ep.IsZero() {
		return nil, errors.New("zitadel: the endpoint is not set; build it with zitadelconn.New or zitadelconn.FromEnv")
	}
	if len(scopes) == 0 {
		return nil, errors.New("zitadel: a token needs at least one scope")
	}
	cfg := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ep.TokenURL(),
		Scopes:       scopes,
	}
	hctx := context.WithValue(ctx, oauth2.HTTPClient, ep.HTTPClient(tokenTimeout))
	return oauth2.ReuseTokenSource(nil, cfg.TokenSource(hctx)), nil
}
