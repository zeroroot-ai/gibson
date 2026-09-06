// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package harness

import "testing"

func TestAgentEgressCeiling(t *testing.T) {
	if agentEgressCeiling("") != nil {
		t.Error("no dispatching agent must be unrestricted (nil)")
	}
	if agentEgressCeiling("not-a-catalog-agent") != nil {
		t.Error("a non-catalog agent must be unrestricted (nil)")
	}
}
