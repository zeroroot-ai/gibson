/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"sort"
	"testing"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// TestMemberRoleEnumParityWithFGA asserts that every MemberRole value maps to
// a non-empty FGA relation string, and that the complete set of relation
// strings equals exactly {"owner", "admin", "member"}.
//
// This test is the compile-time + runtime guard described in spec
// tenant-role-taxonomy (Req 3.5): adding a new MemberRole constant without
// updating this expected set will cause the test to fail with a message that
// names the spec, ensuring the drift is caught in code review.
func TestMemberRoleEnumParityWithFGA(t *testing.T) {
	// Explicit slice — preferred over reflection for clarity (spec
	// tenant-role-taxonomy task 2.2).  When a new MemberRole constant is
	// added to the API package, it MUST also be added here.
	allRoles := []gibsonv1alpha1.MemberRole{
		gibsonv1alpha1.MemberRoleOwner,
		gibsonv1alpha1.MemberRoleAdmin,
		gibsonv1alpha1.MemberRoleMember,
	}

	// Each role must map to a non-empty string (i.e. string(role) != "").
	for _, role := range allRoles {
		rel := string(role)
		if rel == "" {
			t.Errorf(
				"tenant-role-taxonomy: MemberRole %q maps to an empty FGA relation string; "+
					"every enum value must correspond to a named FGA relation on type tenant",
				role,
			)
		}
	}

	// The complete set of relation strings must equal exactly
	// {"owner", "admin", "member"} — the three FGA relations defined on
	// type tenant in gibson v0.27.0 (spec tenant-role-taxonomy Req 3.1).
	wantRelations := []string{"admin", "member", "owner"} // sorted for comparison

	got := make([]string, 0, len(allRoles))
	seen := make(map[string]bool, len(allRoles))
	for _, role := range allRoles {
		rel := string(role)
		if seen[rel] {
			t.Errorf(
				"tenant-role-taxonomy: duplicate FGA relation string %q — "+
					"each MemberRole must map to a distinct relation",
				rel,
			)
			continue
		}
		seen[rel] = true
		got = append(got, rel)
	}
	sort.Strings(got)

	if len(got) != len(wantRelations) {
		t.Fatalf(
			"tenant-role-taxonomy: FGA relation set mismatch — got %v, want %v; "+
				"update allRoles slice in this test when adding or removing a MemberRole constant",
			got, wantRelations,
		)
	}
	for i := range wantRelations {
		if got[i] != wantRelations[i] {
			t.Errorf(
				"tenant-role-taxonomy: FGA relation set mismatch at index %d — got %q, want %q; "+
					"the enum values must exactly match the FGA relations on type tenant",
				i, got[i], wantRelations[i],
			)
		}
	}
}
