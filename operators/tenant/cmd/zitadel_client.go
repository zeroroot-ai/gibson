// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// newZitadelClient builds the operator's Zitadel client. It authenticates as
// the operator's own machine user with a client_credentials token, never with
// the Zitadel owner credentials.
func newZitadelClient(ctx context.Context, ep zitadelconn.Endpoint, clientID, clientSecret string) (zitadel.Client, error) {
	tokens, err := zitadel.TokenSource(ctx, ep, clientID, clientSecret, zitadel.APIScopes())
	if err != nil {
		return nil, fmt.Errorf("zitadel client: %w", err)
	}
	c, err := zitadel.New(ep, tokens)
	if err != nil {
		return nil, fmt.Errorf("zitadel client: %w", err)
	}
	return c, nil
}

// newPlatformTokenSource builds the token source for the operator's calls to
// the dashboard's provisioning API. The token comes from the same in-cluster
// Zitadel Service as every other identity call (ADR-0092). Before gibson#222
// this one request went to the public issuer, so it passed through Envoy and
// failed on every Envoy restart.
func newPlatformTokenSource(ctx context.Context, ep zitadelconn.Endpoint, clientID, clientSecret string) (oauth2.TokenSource, error) {
	tokens, err := zitadel.TokenSource(ctx, ep, clientID, clientSecret, zitadel.PlatformScopes())
	if err != nil {
		return nil, fmt.Errorf("platform token source: %w", err)
	}
	return tokens, nil
}

// newTenantRoleGrants builds the Zitadel half of the tenant role Syncer
// (ADR-0093 decision 3). It calls the v2 Connect services by Service name and
// claims the instance by header (ADR-0092), as the operator's own machine
// user with the same client credentials as newZitadelClient.
func newTenantRoleGrants(ctx context.Context, ep zitadelconn.Endpoint, clientID, clientSecret, projectID string) (tenantrole.Grants, error) {
	tokens, err := zitadel.TokenSource(ctx, ep, clientID, clientSecret, zitadel.APIScopes())
	if err != nil {
		return nil, fmt.Errorf("tenant role grants: %w", err)
	}
	hc := &http.Client{Transport: &oauth2.Transport{Source: tokens, Base: ep.Transport(nil)}}
	return tenantrole.NewZitadelGrants(ep, hc, projectID), nil
}
