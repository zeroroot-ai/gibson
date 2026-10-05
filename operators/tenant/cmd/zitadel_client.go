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

// zitadelWiring is everything the operator builds from its Zitadel
// configuration at startup.
type zitadelWiring struct {
	// endpoint is the one way the operator reaches Zitadel (ADR-0092): it
	// connects to the in-cluster Service (ZITADEL_URL) and claims the public
	// host (ZITADEL_EXTERNAL_DOMAIN) with the instance header.
	endpoint zitadelconn.Endpoint
	// tokens are the operator's two token sources, both for its own
	// machine user.
	tokens zitadel.TokenSources
	// client is the Management API client.
	client zitadel.Client
}

// newZitadelWiring reads the operator's Zitadel configuration and builds the
// endpoint, the platform token source and the Management client from it.
// Every Zitadel call uses the one endpoint. No call builds a URL from an
// issuer, so no call depends on hostAliases or on Envoy (gibson#222).
//
// Required env vars: ZITADEL_URL, ZITADEL_EXTERNAL_DOMAIN,
// ZITADEL_TENANT_OPERATOR_CLIENT_ID and ZITADEL_TENANT_OPERATOR_CLIENT_SECRET.
// A missing one is an error, and the operator refuses to start (one-code-path
// / deploy#196): it would otherwise surface days later as a Ready tenant with
// no Zitadel org.
func newZitadelWiring(ctx context.Context, getenv func(string) string) (*zitadelWiring, error) {
	ep, err := zitadelconn.New(getenv(zitadelconn.EnvURL), getenv(zitadelconn.EnvExternalDomain))
	if err != nil {
		return nil, fmt.Errorf("zitadel endpoint (ADR-0092): %w", err)
	}
	// The operator authenticates as its own machine user with
	// client_credentials tokens, never with the Zitadel owner credentials.
	// Before gibson#222 the platform token request went to the public issuer,
	// so it passed through Envoy and failed on every Envoy restart.
	tokens, err := zitadel.NewTokenSources(ctx, ep, getenv("ZITADEL_TENANT_OPERATOR_CLIENT_ID"), getenv("ZITADEL_TENANT_OPERATOR_CLIENT_SECRET"))
	if err != nil {
		return nil, fmt.Errorf("zitadel tokens: set ZITADEL_TENANT_OPERATOR_CLIENT_ID and ZITADEL_TENANT_OPERATOR_CLIENT_SECRET: %w", err)
	}
	return &zitadelWiring{endpoint: ep, tokens: tokens, client: zitadel.New(ep, tokens.API)}, nil
}

// zitadelWiringOrExit is newZitadelWiring for main: on an error it logs the
// cause and calls exit(1), so a tenant-operator with an incomplete Zitadel
// configuration shows as a CrashLoopBackOff and never as a running pod.
func zitadelWiringOrExit(ctx context.Context, getenv func(string) string, exit func(int)) *zitadelWiring {
	w, err := newZitadelWiring(ctx, getenv)
	if err != nil {
		setupLog.Error(err, "Zitadel wiring: the operator refuses to start")
		exit(1)
	}
	return w
}

// tenantRoleGrants builds the Zitadel half of the tenant role Syncer
// (ADR-0093 decision 3). It calls the v2 Connect services by Service name and
// claims the instance by header (ADR-0092), as the operator's own machine
// user with the same token source as the Management client.
func (w *zitadelWiring) tenantRoleGrants(projectID string) tenantrole.Grants {
	hc := &http.Client{Transport: &oauth2.Transport{Source: w.tokens.API, Base: w.endpoint.Transport(nil)}}
	return tenantrole.NewZitadelGrants(w.endpoint, hc, projectID)
}
