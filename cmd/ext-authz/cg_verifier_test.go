// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"net/http"
	"strings"
	"testing"
)

// TestBuildCGVerifier_RequiresIssuer — enabling the keys URL without pinning
// the expected issuer must fail startup rather than accept CG-JWTs from an
// unpinned issuer.
func TestBuildCGVerifier_RequiresIssuer(t *testing.T) {
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://daemon:8086/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_CGJWT_ISSUER", "")

	v, err := buildCGVerifier(&http.Client{})
	if err == nil {
		t.Fatalf("buildCGVerifier = %v, nil — it must refuse to start with an unpinned issuer", v)
	}
	if !strings.Contains(err.Error(), "EXT_AUTHZ_CGJWT_ISSUER") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

// TestBuildCGVerifier_WiresConfig proves a valid config actually reaches
// cgjwt.NewVerifier: a verifier is only returned when the keys URL and
// issuer are both set.
func TestBuildCGVerifier_WiresConfig(t *testing.T) {
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://daemon:8086/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_CGJWT_ISSUER", "gibson-daemon")

	v, err := buildCGVerifier(&http.Client{})
	if err != nil {
		t.Fatalf("buildCGVerifier: %v", err)
	}
	if v == nil {
		t.Fatal("buildCGVerifier returned no verifier despite a valid config")
	}
}
