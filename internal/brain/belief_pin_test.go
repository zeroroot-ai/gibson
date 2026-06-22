package brain

import "testing"

// TestMission_PinsBeliefModelVersion proves a mission records the belief-model
// version it ran under (ADR-0005 §5) and that replay reproduces the pin — the
// deterministic-replay guarantee for the belief field.
func TestMission_PinsBeliefModelVersion(t *testing.T) {
	e := NewEngine("t")
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path", BeliefModel: "base-v1"})
	e.Tick()

	ms := e.World.MissionSnapshot()
	if len(ms) != 1 {
		t.Fatalf("got %d missions, want 1", len(ms))
	}
	if ms[0].BeliefModel != "base-v1" {
		t.Fatalf("mission did not pin belief model: %q", ms[0].BeliefModel)
	}

	// Replay reproduces the pin (the MissionProjected event carries it).
	r := Replay("t", e.Timeline)
	if rm := r.MissionSnapshot(); len(rm) != 1 || rm[0].BeliefModel != "base-v1" {
		t.Fatalf("replay lost the pinned belief model: %+v", rm)
	}
}

// TestMissionStarted_PinsBeliefModelVersion proves the minimal launch path also
// carries the pin.
func TestMissionStarted_PinsBeliefModelVersion(t *testing.T) {
	e := NewEngine("t")
	e.Submit(MissionStarted{ID: "m1", Goal: "g", BeliefModel: "base-v2"})
	e.Tick()
	ms := e.World.MissionSnapshot()
	if len(ms) != 1 || ms[0].BeliefModel != "base-v2" {
		t.Fatalf("MissionStarted did not pin belief model: %+v", ms)
	}
}
