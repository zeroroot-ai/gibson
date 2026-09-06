// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package componentcatalog

import "testing"

func TestLookupEgress(t *testing.T) {
	// gitlab is a shipped connector manifest with egressAllow: [gitlab.com:443].
	allow, ok := LookupEgress("connector", "gitlab")
	if !ok {
		t.Fatal("gitlab connector should be in the catalog")
	}
	if len(allow) == 0 {
		t.Errorf("gitlab should declare an egress ceiling, got %v", allow)
	}
	if _, ok := LookupEgress("agent", "does-not-exist"); ok {
		t.Error("unknown component must report not found")
	}
	if _, ok := LookupEgress("connector", "does-not-exist"); ok {
		t.Error("unknown id must report not found")
	}
}
