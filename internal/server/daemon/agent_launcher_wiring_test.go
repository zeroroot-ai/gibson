// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package daemon

import (
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

func TestAgentLauncherWiring(t *testing.T) {
	if wire, warn := agentLauncherWiring(nil, errors.New("boom")); wire || warn == "" {
		t.Errorf("construction error: got (wire=%v, warn=%q), want (false, non-empty)", wire, warn)
	}
	if wire, warn := agentLauncherWiring(nil, nil); wire || warn == "" {
		t.Errorf("nil launcher (disabled build): got (wire=%v, warn=%q), want (false, non-empty)", wire, warn)
	}
	if wire, warn := agentLauncherWiring(&sandboxed.AgentLauncher{}, nil); !wire || warn != "" {
		t.Errorf("real launcher: got (wire=%v, warn=%q), want (true, empty)", wire, warn)
	}
}

// TestNewSetecAgentLauncher_DisabledBuild pins the default (un-tagged) build's
// fail-closed behavior: no setec client is compiled in, so the constructor
// returns (nil, nil) and an untrusted agent is denied rather than run.
func TestNewSetecAgentLauncher_DisabledBuild(t *testing.T) {
	l, err := NewSetecAgentLauncher(config.SandboxConfig{}, nil, nil, nil)
	if l != nil || err != nil {
		t.Fatalf("disabled build: got (%v, %v), want (nil, nil)", l, err)
	}
}
