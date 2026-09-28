// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeOrgTenantLookup struct {
	tenant string
	err    error
}

func (f *fakeOrgTenantLookup) TenantForOrg(_ context.Context, _ string) (string, error) {
	return f.tenant, f.err
}

func TestOrgTenantHandler_Mapped(t *testing.T) {
	lookup := &fakeOrgTenantLookup{tenant: "acme"}
	resp := serveMux(t, orgTenantHandler(lookup), orgTenantPath+"123")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var doc orgTenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if doc.TenantID != "acme" {
		t.Fatalf("tenant_id = %q, want acme", doc.TenantID)
	}
}

func TestOrgTenantHandler_Unmapped_Returns200EmptyNever404(t *testing.T) {
	// A 404 must mean the route itself is absent (an old daemon), never
	// "this org has no tenant" — ext-authz's version-skew handling treats a
	// 404 as an error and fails closed. See orgTenantHandler's doc comment.
	lookup := &fakeOrgTenantLookup{tenant: ""}
	resp := serveMux(t, orgTenantHandler(lookup), orgTenantPath+"999")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unmapped is not a 404)", resp.StatusCode)
	}
	var doc orgTenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if doc.TenantID != "" {
		t.Fatalf("tenant_id = %q, want empty", doc.TenantID)
	}
}

func TestOrgTenantHandler_EmptyOrgID_Returns400(t *testing.T) {
	lookup := &fakeOrgTenantLookup{tenant: "acme"}
	resp := serveMux(t, orgTenantHandler(lookup), orgTenantPath)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOrgTenantHandler_MalformedOrgID_Returns400(t *testing.T) {
	lookup := &fakeOrgTenantLookup{tenant: "acme"}
	resp := serveMux(t, orgTenantHandler(lookup), orgTenantPath+"has spaces")

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOrgTenantHandler_DBError_Returns500(t *testing.T) {
	lookup := &fakeOrgTenantLookup{err: errors.New("boom")}
	resp := serveMux(t, orgTenantHandler(lookup), orgTenantPath+"123")

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestOrgTenantHandler_RejectsNonGET(t *testing.T) {
	lookup := &fakeOrgTenantLookup{tenant: "acme"}
	srv := httptest.NewServer(orgTenantHandler(lookup))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+orgTenantPath+"123", "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", orgTenantPath, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status = %d, want 405", resp.StatusCode)
	}
}

func TestAuthzRegistryMux_MountsOrgTenantRouteOnlyWithALookup(t *testing.T) {
	// Absent: 404, not mounted-but-broken.
	resp := serveMux(t, authzRegistryMux(nil, nil, nil), orgTenantPath+"123")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unmounted org-tenant route: status = %d, want 404", resp.StatusCode)
	}

	// Present: served.
	lookup := &fakeOrgTenantLookup{tenant: "acme"}
	resp2 := serveMux(t, authzRegistryMux(nil, nil, lookup), orgTenantPath+"123")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("mounted org-tenant route: status = %d, want 200", resp2.StatusCode)
	}
}

func TestOrgTenantSource_MapsNilPointerToNilInterface(t *testing.T) {
	if orgTenantSource(nil) != nil {
		t.Fatal("orgTenantSource(nil) must be a nil interface, not a non-nil interface holding a nil pointer")
	}
}

func TestIsValidZitadelOrgID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"123456789012345", true},
		{"has spaces", false},
		{"a-b_c", true},
		{"../../etc/passwd", false},
		{string(make([]byte, 65)), false}, // too long (NUL bytes, but length alone fails)
	}
	for _, c := range cases {
		if got := isValidZitadelOrgID(c.in); got != c.want {
			t.Errorf("isValidZitadelOrgID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
