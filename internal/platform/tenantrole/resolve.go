// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole

import "github.com/zeroroot-ai/gibson/internal/platform/authz"

// RoleChecks returns the FGA checks that resolve the tenant role of user on
// tenantObject, highest relation first: owner, admin, writer, member.
//
// Every surface that reports a tenant role sends these checks and reads the
// answers with HighestRelation. The member list and the caller's own
// membership then cannot disagree about one person (gibson#482).
func RoleChecks(user, tenantObject string) []authz.CheckRequest {
	checks := make([]authz.CheckRequest, len(Relations))
	for i, rel := range Relations {
		checks[i] = authz.CheckRequest{User: user, Relation: rel, Object: tenantObject}
	}
	return checks
}

// HighestRelation returns the highest relation held, given the answers to
// RoleChecks in the same order. The FGA model computes each relation from the
// one above it, so an Owner answers true to all four and the first true
// answer wins. ok is false when the user holds no relation: no surface may
// then report a role.
func HighestRelation(held []bool) (relation string, ok bool) {
	for i, rel := range Relations {
		if i < len(held) && held[i] {
			return rel, true
		}
	}
	return "", false
}
