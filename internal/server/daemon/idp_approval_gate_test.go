// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import "testing"

func TestRequireIDPAdminForApproval(t *testing.T) {
	if err := requireIDPAdminForApproval(false, true); err == nil {
		t.Error("the approval rung without the IdP admin client must refuse to start")
	}
	for _, c := range []struct{ idp, approval bool }{{true, true}, {false, false}, {true, false}} {
		if err := requireIDPAdminForApproval(c.idp, c.approval); err != nil {
			t.Errorf("idp=%v approval=%v: unexpected error %v", c.idp, c.approval, err)
		}
	}
}
