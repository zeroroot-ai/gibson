// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestFindingUpsertParams_CarriesTheSubmitter (gibson#208): the projector
// writes the verified submitter onto the :Finding node, so a reader of the
// tenant graph can tell which agent raised a finding and who enrolled it.
func TestFindingUpsertParams_CarriesTheSubmitter(t *testing.T) {
	t.Parallel()

	p := findingUpsertParams(brain.FindingSnapshot{
		ID: "f1", SubmittedBy: "agent_principal:sa-1", AgentName: "zerocool-demo", EnrolledBy: "user-9",
	})
	if p["submitted_by"] != "agent_principal:sa-1" || p["agent_name"] != "zerocool-demo" || p["enrolled_by"] != "user-9" {
		t.Errorf("params = %+v, want the submitter", p)
	}
	for _, want := range []string{
		"f.submitted_by = $submitted_by",
		"f.agent_name = $agent_name",
		"f.enrolled_by = $enrolled_by",
	} {
		if !strings.Contains(upsertFindingCypher, want) {
			t.Errorf("upsertFindingCypher is missing %q:\n%s", want, upsertFindingCypher)
		}
	}
}
