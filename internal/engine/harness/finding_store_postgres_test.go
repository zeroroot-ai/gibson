// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// A finding that names the daemon record of a read of a connector tool was
// raised by that read, and any other finding by its mission run. A tool name
// that an agent typed as tier 2 text does not count (review m2).
func TestSubmittedFindingCheck(t *testing.T) {
	mission := types.NewID()
	recorded := func(tool string) *typespb.Evidence {
		return &typespb.Evidence{Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, Metadata: map[string]string{"tool_name": tool}}
	}
	typed := &typespb.Evidence{Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED, Metadata: map[string]string{"tool_name": "mcp:qualys-vmdr:get_host_detections"}}
	for name, tc := range map[string]struct {
		evidence []*typespb.Evidence
		want     finding.Check
	}{
		"a connector read": {[]*typespb.Evidence{recorded("mcp:qualys-vmdr:get_host_detections")},
			finding.Check{Kind: finding.CheckTool, Ref: "mcp:qualys-vmdr:get_host_detections"}},
		"a native tool": {[]*typespb.Evidence{recorded("nmap")}, finding.ScanCheck(mission)},
		"typed text":    {[]*typespb.Evidence{typed}, finding.ScanCheck(mission)},
		"no evidence":   {nil, finding.ScanCheck(mission)},
	} {
		f := agent.Finding{Evidence: tc.evidence}
		if got := SubmittedFindingCheck(f, mission); got != tc.want {
			t.Errorf("%s: check = %+v, want %+v", name, got, tc.want)
		}
	}
}
