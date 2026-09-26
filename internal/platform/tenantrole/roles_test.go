// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

// TestAll_HasExactlyTheFourTenantRolesInOrder pins the declared set the
// platform-operator's EnsureProjectRoles creates on the gibson project.
// The FGA-relation mapping and the Zitadel-key/FGA-relation helpers land
// with the rest of the tenantrole package in a later change.
func TestAll_HasExactlyTheFourTenantRolesInOrder(t *testing.T) {
	want := []tenantrole.Def{
		{tenantrole.Owner, "Owner"},
		{tenantrole.Admin, "Admin"},
		{tenantrole.Editor, "Editor"},
		{tenantrole.Viewer, "Viewer"},
	}
	if len(tenantrole.All) != len(want) {
		t.Fatalf("All = %+v, want %+v", tenantrole.All, want)
	}
	for i, d := range want {
		if tenantrole.All[i] != d {
			t.Errorf("All[%d] = %+v, want %+v", i, tenantrole.All[i], d)
		}
	}
}
