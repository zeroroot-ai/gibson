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
func newZitadelClient(ctx context.Context, apiURL, externalDomain, clientID, clientSecret string) (zitadel.Client, error) {
	tokens, err := zitadel.TokenSource(ctx, apiURL, externalDomain, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("zitadel client: %w", err)
	}
	return zitadel.New(apiURL, tokens, externalDomain), nil
}

// newTenantRoleGrants builds the Zitadel half of the tenant role Syncer
// (ADR-0093 decision 3). It calls the v2 Connect services by Service name and
// claims the instance by header (ADR-0092), as the operator's own machine
// user with the same client credentials as newZitadelClient.
func newTenantRoleGrants(ctx context.Context, apiURL, externalDomain, clientID, clientSecret, projectID string) (tenantrole.Grants, error) {
	ep, err := zitadelconn.New(apiURL, externalDomain)
	if err != nil {
		return nil, fmt.Errorf("tenant role grants: %w", err)
	}
	tokens, err := zitadel.TokenSource(ctx, apiURL, externalDomain, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("tenant role grants: %w", err)
	}
	hc := &http.Client{Transport: &oauth2.Transport{Source: tokens, Base: ep.Transport(nil)}}
	return tenantrole.NewZitadelGrants(ep, hc, projectID), nil
}
