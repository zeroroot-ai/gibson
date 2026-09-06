// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package config

import "testing"

// TestSandboxConfig_DefaultsAgentSandboxClass pins the AgentSandboxClass
// defaulting in Validate (ADR-0016 / gibson#1596). The class default is applied
// before the later mTLS/cert checks, so this asserts the side-effect directly
// and does not depend on a fully valid mTLS config — an empty class must never
// reach the launcher (it would defer to the cluster-default posture, ADR-0052).
func TestSandboxConfig_DefaultsAgentSandboxClass(t *testing.T) {
	c := &SandboxConfig{Enabled: true, Setec: SandboxSetecConfig{Address: "setec:8443", Tenant: "gibson"}}
	_ = c.Validate() // may fail later on mTLS; the class default runs first
	if c.Setec.AgentSandboxClass != DefaultAgentSandboxClass {
		t.Fatalf("AgentSandboxClass = %q, want default %q", c.Setec.AgentSandboxClass, DefaultAgentSandboxClass)
	}

	explicit := &SandboxConfig{Enabled: true, Setec: SandboxSetecConfig{Address: "setec:8443", Tenant: "gibson", AgentSandboxClass: "hardened-agent"}}
	_ = explicit.Validate()
	if explicit.Setec.AgentSandboxClass != "hardened-agent" {
		t.Fatalf("explicit AgentSandboxClass overwritten to %q", explicit.Setec.AgentSandboxClass)
	}
}
