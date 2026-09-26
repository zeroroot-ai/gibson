// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// orgTenantPath is the daemon's org->tenant lookup route (ADR-0093
// decision 4, hosted#195). ext-authz calls it over the same SVID-pinned mTLS
// listener that already serves the authz registry and the Capability-Grant
// keys, to resolve a signed-in person's tenant from their token's verified
// Zitadel org — never from a client-supplied x-gibson-tenant header.
const orgTenantPath = "/identity/v1/org-tenant/"

// orgTenantLookup is the one read the route needs.
type orgTenantLookup interface {
	// TenantForOrg returns the tenant mapped to zitadelOrgID, or ("", nil)
	// when the org maps to no tenant.
	TenantForOrg(ctx context.Context, zitadelOrgID string) (tenantID string, err error)
}

// orgTenantResponse is the route's JSON body.
type orgTenantResponse struct {
	TenantID string `json:"tenant_id"`
}

// orgTenantHandler answers GET /identity/v1/org-tenant/{orgID}:
//
//	200 {"tenant_id":"acme"}   mapped
//	200 {"tenant_id":""}       no tenant (the org is not a tenant)
//	400                         empty or malformed org id
//	405                         non-GET
//	500                         database error
//
// "Unmapped" is a 200 with an empty value, never a 404. A 404 must mean the
// route itself is absent (an old daemon): ext-authz treats a 404 as an
// error and fails closed with 503, so a version-skewed daemon never reads
// as "this person has no tenant."
func orgTenantHandler(lookup orgTenantLookup) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orgID := strings.TrimPrefix(r.URL.Path, orgTenantPath)
		if !isValidZitadelOrgID(orgID) {
			http.Error(w, "invalid org id", http.StatusBadRequest)
			return
		}
		tenantID, err := lookup.TenantForOrg(r.Context(), orgID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(orgTenantResponse{TenantID: tenantID})
	}
}

// isValidZitadelOrgID mirrors the validation ext-authz's orgtenant.Resolver
// applies before it ever calls this route (non-empty, max 64 chars,
// [0-9A-Za-z_-] only — Zitadel org ids are numeric strings). Refusing an
// out-of-shape id here too is defense in depth, never the only check.
func isValidZitadelOrgID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}
