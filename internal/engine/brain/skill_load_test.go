// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

func skillLoadEvents() []Event {
	return []Event{
		AgentSkillLoaded{
			MissionID: "m1", RunID: "r1", Agent: "agent_principal:a1", Name: "web-recon",
			Digest: "sha256:aa", RecordedAtUnixNano: 10,
		},
		AgentSkillLoaded{
			MissionID: "m1", RunID: "r1", Agent: "agent_principal:a1", Name: "web-recon",
			Digest: "sha256:aa", File: "references/a.md", RecordedAtUnixNano: 20,
		},
	}
}

// One load gives one event, and the World holds the digest that the agent got.
func TestAgentSkillLoaded_TheWorldShowsEachLoad(t *testing.T) {
	w := NewWorld("acme")
	for _, ev := range skillLoadEvents() {
		Reduce(w, ev)
	}
	loads := w.AgentSkillLoads()
	if len(loads) != 2 {
		t.Fatalf("loads = %d, want 2", len(loads))
	}
	if loads[0].Digest != "sha256:aa" || loads[0].MissionID != "m1" || loads[0].Agent != "agent_principal:a1" ||
		loads[0].Name != "web-recon" || loads[1].File != "references/a.md" {
		t.Errorf("loads = %+v", loads)
	}
	// A reader cannot change the World through the returned slice.
	loads[0].Digest = "changed"
	if w.AgentSkillLoads()[0].Digest != "sha256:aa" {
		t.Error("AgentSkillLoads returned the slice of the World")
	}
}

func TestAgentSkillLoaded_ReplaysThroughTheCodecAndTheSnapshot(t *testing.T) {
	tl := &Timeline{}
	for _, ev := range skillLoadEvents() {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("EncodeEvent: %v", err)
		}
		back, err := DecodeEvent(data)
		if err != nil {
			t.Fatalf("DecodeEvent: %v", err)
		}
		tl.Append(back)
	}
	w := Replay("acme", tl)
	if len(w.AgentSkillLoads()) != 2 {
		t.Fatalf("a replay of the decoded events gave %d loads, want 2", len(w.AgentSkillLoads()))
	}
	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "acme")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.AgentSkillLoads(), w.AgentSkillLoads(); !reflect.DeepEqual(got, want) {
		t.Fatalf("loads did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}
