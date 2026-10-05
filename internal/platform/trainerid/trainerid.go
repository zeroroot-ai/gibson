// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package trainerid names the SPIFFE identity of the belief trainer of a
// tenant (ADR-0106, gibson#788): spiffe://<trust domain>/trainer/<tenant>.
// The tenant operator registers it for the CronJob of the tenant, and the
// daemon accepts it for the two trainer RPCs of that tenant only.
package trainerid

import (
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// PathPrefix starts the path of a trainer identity.
const PathPrefix = "/trainer/"

// tenantRe is the rule for the tenant segment: a DNS label, as a tenant
// namespace name needs.
var tenantRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Tenant returns the tenant of a trainer identity in the trust domain td, and
// false for each other ID: another trust domain, another path form, or a
// tenant segment that is not a DNS label.
func Tenant(id spiffeid.ID, td spiffeid.TrustDomain) (string, bool) {
	if id.TrustDomain() != td {
		return "", false
	}
	tenant, ok := strings.CutPrefix(id.Path(), PathPrefix)
	if !ok || !tenantRe.MatchString(tenant) {
		return "", false
	}
	return tenant, true
}

// TenantOfString parses raw and returns its tenant, as Tenant does.
func TenantOfString(raw string, td spiffeid.TrustDomain) (string, bool) {
	id, err := spiffeid.FromString(raw)
	if err != nil {
		return "", false
	}
	return Tenant(id, td)
}
