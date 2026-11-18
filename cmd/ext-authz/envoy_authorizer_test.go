// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"strings"
	"testing"
)

// ext-authz refuses to start with no Envoy SVID, and the error names an
// example in example.org, never a real trust domain (ADR-0164).
func TestBuildEnvoyAuthorizer_RequiresTheEnvoySVID(t *testing.T) {
	t.Setenv("EXT_AUTHZ_ENVOY_SVID", "")
	_, _, _, err := buildPeerPolicy()
	if err == nil {
		t.Fatal("buildPeerPolicy accepted an empty EXT_AUTHZ_ENVOY_SVID")
	}
	if !strings.Contains(err.Error(), "spiffe://example.org/") {
		t.Errorf("error %q does not give an example.org example", err)
	}
}

// An Envoy SVID in any trust domain builds an authorizer.
func TestBuildEnvoyAuthorizer_AcceptsAnyTrustDomain(t *testing.T) {
	t.Setenv("EXT_AUTHZ_ENVOY_SVID", "spiffe://example.org/platform/envoy")
	if _, _, _, err := buildPeerPolicy(); err != nil {
		t.Fatalf("buildPeerPolicy: %v", err)
	}
}

// The gateway identity is optional. With it set, both lists come back.
func TestBuildPeerPolicy_GatewayIdentity(t *testing.T) {
	t.Setenv("EXT_AUTHZ_ENVOY_SVID", "spiffe://example.org/platform/envoy")
	t.Setenv("EXT_AUTHZ_GATEWAY_SVID", "")
	_, edge, gw, err := buildPeerPolicy()
	if err != nil || len(edge) != 1 || len(gw) != 0 {
		t.Fatalf("no gateway: %v %v %v", edge, gw, err)
	}
	t.Setenv("EXT_AUTHZ_GATEWAY_SVID", "spiffe://example.org/platform/agentgateway, spiffe://example.org/platform/agentgateway-b")
	_, edge, gw, err = buildPeerPolicy()
	if err != nil || len(edge) != 1 || len(gw) != 2 || gw[0] != "spiffe://example.org/platform/agentgateway" {
		t.Fatalf("gateway: %v %v %v", edge, gw, err)
	}
	t.Setenv("EXT_AUTHZ_GATEWAY_SVID", "not a spiffe id")
	if _, _, _, err := buildPeerPolicy(); err == nil {
		t.Error("an invalid gateway SVID gave no error")
	}
}
