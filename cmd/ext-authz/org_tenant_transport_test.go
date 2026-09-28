// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"strings"
	"testing"
)

// The org->tenant lookup determines a signed-in person's tenant (ADR-0093
// decision 4), so it gets the identical treatment as the Capability-Grant
// keys fetch: required, https-only, SVID-pinned. These tests exercise the
// startup-time validation; the fetch and cache behavior itself is covered
// in internal/server/extauthz/orgtenant.

func TestBuildOrgTenantResolver_RequiresTheURL(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_ORG_TENANT_URL", "")
	if r, err := buildOrgTenantResolver(discardLogger(), extAuthz, extAuthz); err == nil {
		t.Fatalf("buildOrgTenantResolver = %v, nil — the URL must be required", r)
	} else if !strings.Contains(err.Error(), "EXT_AUTHZ_ORG_TENANT_URL") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

func TestBuildOrgTenantResolver_RefusesPlaintext(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_ORG_TENANT_URL", "http://gibson:8086/identity/v1/org-tenant/")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)
	if r, err := buildOrgTenantResolver(discardLogger(), extAuthz, extAuthz); err == nil {
		t.Fatalf("buildOrgTenantResolver = %v, nil — a plaintext URL must fail startup", r)
	} else if !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want it to name the https requirement", err)
	}
}

func TestBuildOrgTenantResolver_RefusesUnparseableURL(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_ORG_TENANT_URL", "https://gibson:8086/\x7f/org-tenant/")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)
	if r, err := buildOrgTenantResolver(discardLogger(), extAuthz, extAuthz); err == nil {
		t.Fatalf("buildOrgTenantResolver = %v, nil — an unparseable URL must fail startup", r)
	} else if !strings.Contains(err.Error(), "EXT_AUTHZ_ORG_TENANT_URL") {
		t.Fatalf("err = %v, want it to name the variable", err)
	}
}

func TestBuildOrgTenantResolver_RequiresDaemonSVID(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_ORG_TENANT_URL", "https://gibson:8086/identity/v1/org-tenant/")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", "")
	if r, err := buildOrgTenantResolver(discardLogger(), extAuthz, extAuthz); err == nil {
		t.Fatalf("buildOrgTenantResolver = %v, nil — an https URL with no pin must fail startup", r)
	} else if !strings.Contains(err.Error(), "EXT_AUTHZ_DAEMON_SVID") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

func TestBuildOrgTenantResolver_SucceedsWithAWellFormedURL(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_ORG_TENANT_URL", "https://gibson:8086/identity/v1/org-tenant/")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)
	r, err := buildOrgTenantResolver(discardLogger(), extAuthz, extAuthz)
	if err != nil {
		t.Fatalf("buildOrgTenantResolver: %v", err)
	}
	if r == nil {
		t.Fatal("buildOrgTenantResolver returned a nil resolver with no error")
	}
}
