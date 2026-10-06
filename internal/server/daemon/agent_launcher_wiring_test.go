// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package daemon

import (
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
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
