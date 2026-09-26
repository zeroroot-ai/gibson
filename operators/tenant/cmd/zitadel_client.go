// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// zitadelManagementScopes is the OAuth2 scope that gets Zitadel's Management/
// v2 API audience into the issued access token (the same scope the daemon's
// idp/zitadel admin client requests). It is distinct from the
// urn:zitadel:iam:org:project:id:gibson-platform:aud scope requested
// elsewhere in this binary for the dashboard-audience token — same machine
// user, two different token audiences.
var zitadelManagementScopes = []string{"openid", "urn:zitadel:iam:org:project:id:zitadel:aud"}

// buildTenantOperatorZitadelClient builds the operator's Zitadel Management
// API client, authenticated as the operator's own Zitadel machine user (the
// gibson-zitadel-tenant-operator OIDCClient) via an OAuth2 client_credentials
// grant, instead of the shared IAM_OWNER Personal Access Token this operator
// used before hosted#200. clientID/clientSecret are the operator's own
// credentials (ZITADEL_TENANT_OPERATOR_CLIENT_ID/_SECRET), already required
// for the dashboard-audience token built elsewhere in this binary.
//
// The connection goes in-cluster with the public host claimed by header
// (ADR-0092, zitadelconn), not the public zitadelIssuer used for the
// dashboard-audience token, because Zitadel's Management/v2 API rejects
// admin writes that cross the public edge (gibson#1560).
//
// Pure given its inputs: zitadelconn.New only validates the two connection
// facts, and no network call happens until the returned client's first
// request obtains a token lazily (oauth2.ReuseTokenSource refreshes it
// automatically thereafter). This makes the whole function unit-testable
// without a live Zitadel.
func buildTenantOperatorZitadelClient(clientID, clientSecret, zitadelURL, externalDomain string) (zitadel.Client, error) {
	endpoint, err := zitadelconn.New(zitadelURL, externalDomain)
	if err != nil {
		return nil, fmt.Errorf("zitadelconn.New (ADR-0092): %w", err)
	}
	ccCfg := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     endpoint.TokenURL(),
		Scopes:       zitadelManagementScopes,
	}
	base := &http.Client{Timeout: 30 * time.Second, Transport: endpoint.Transport(nil)}
	tokens := oauth2.ReuseTokenSource(nil,
		ccCfg.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, base)))
	return zitadel.New(zitadelURL, tokens, externalDomain), nil
}
