// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// The creator rides MissionStarted into the World, out through the mission
// snapshot, and back in through a World snapshot restore (hosted#205), so
// ListMissions serves it without a secondary store and a restarted daemon
// keeps it.
func TestMissionStarted_CreatorFoldsAndSurvivesRestore(t *testing.T) {
	creator := principal.Principal{Kind: principal.User, ID: "123456789012345678"}
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", Name: "scan", TenantID: "t", CreatedBy: creator})

	ms := w.MissionSnapshot()
	if len(ms) != 1 || ms[0].CreatedBy != creator {
		t.Fatalf("snapshot = %+v, want creator %+v", ms, creator)
	}

	restored, err := RestoreWorld(SnapshotWorld(w, "1"), "t")
	if err != nil {
		t.Fatalf("RestoreWorld: %v", err)
	}
	if rs := restored.MissionSnapshot(); len(rs) != 1 || rs[0].CreatedBy != creator {
		t.Fatalf("restored snapshot = %+v, want creator %+v", rs, creator)
	}
}
