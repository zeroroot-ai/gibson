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
	_, err := buildEnvoyAuthorizer()
	if err == nil {
		t.Fatal("buildEnvoyAuthorizer accepted an empty EXT_AUTHZ_ENVOY_SVID")
	}
	if !strings.Contains(err.Error(), "spiffe://example.org/") {
		t.Errorf("error %q does not give an example.org example", err)
	}
}

// An Envoy SVID in any trust domain builds an authorizer.
func TestBuildEnvoyAuthorizer_AcceptsAnyTrustDomain(t *testing.T) {
	t.Setenv("EXT_AUTHZ_ENVOY_SVID", "spiffe://example.org/platform/envoy")
	if _, err := buildEnvoyAuthorizer(); err != nil {
		t.Fatalf("buildEnvoyAuthorizer: %v", err)
	}
}
