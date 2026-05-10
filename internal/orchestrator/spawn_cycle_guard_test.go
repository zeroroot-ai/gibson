package orchestrator

import (
	"context"
	"errors"
	"testing"
)

func TestSpawnCycleGuard_no_record(t *testing.T) {
	g := newSpawnCycleGuard()
	if err := g.ensureNoCycle(context.Background(), "m1", "agent-a", []string{"unknown-id"}); err != nil {
		t.Errorf("first spawn against empty registry should pass: %v", err)
	}
}

func TestSpawnCycleGuard_self_spawn_via_ancestor(t *testing.T) {
	g := newSpawnCycleGuard()
	g.recordSpawn("m1", "node-1", "agent-a", nil)
	err := g.ensureNoCycle(context.Background(), "m1", "agent-a", []string{"node-1"})
	if err == nil {
		t.Fatal("expected cycle error")
	}
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("got=%T want=*CycleError", err)
	}
	if ce.AgentName != "agent-a" {
		t.Errorf("AgentName=%q want=agent-a", ce.AgentName)
	}
}

func TestSpawnCycleGuard_two_step_cycle(t *testing.T) {
	g := newSpawnCycleGuard()
	g.recordSpawn("m1", "node-1", "agent-a", nil)
	g.recordSpawn("m1", "node-2", "agent-b", []string{"node-1"})
	err := g.ensureNoCycle(context.Background(), "m1", "agent-a", []string{"node-2"})
	if err == nil {
		t.Fatal("expected two-step cycle detected")
	}
}

func TestSpawnCycleGuard_five_step_cycle(t *testing.T) {
	g := newSpawnCycleGuard()
	g.recordSpawn("m1", "n1", "agent-a", nil)
	g.recordSpawn("m1", "n2", "agent-b", []string{"n1"})
	g.recordSpawn("m1", "n3", "agent-c", []string{"n2"})
	g.recordSpawn("m1", "n4", "agent-d", []string{"n3"})
	g.recordSpawn("m1", "n5", "agent-e", []string{"n4"})
	err := g.ensureNoCycle(context.Background(), "m1", "agent-a", []string{"n5"})
	if err == nil {
		t.Fatal("expected five-step cycle detected")
	}
}

func TestSpawnCycleGuard_deep_chain_no_cycle(t *testing.T) {
	g := newSpawnCycleGuard()
	g.recordSpawn("m1", "n1", "agent-a", nil)
	g.recordSpawn("m1", "n2", "agent-b", []string{"n1"})
	g.recordSpawn("m1", "n3", "agent-c", []string{"n2"})
	if err := g.ensureNoCycle(context.Background(), "m1", "agent-d", []string{"n3"}); err != nil {
		t.Errorf("non-cyclic deep chain should pass: %v", err)
	}
}

func TestSpawnCycleGuard_per_mission_isolation(t *testing.T) {
	g := newSpawnCycleGuard()
	// agent-a was spawned in m1 — should NOT cycle in m2.
	g.recordSpawn("m1", "n1", "agent-a", nil)
	if err := g.ensureNoCycle(context.Background(), "m2", "agent-a", []string{"n1"}); err != nil {
		t.Errorf("cross-mission ancestor should not cycle: %v", err)
	}
}

func TestSpawnCycleGuard_forget(t *testing.T) {
	g := newSpawnCycleGuard()
	g.recordSpawn("m1", "n1", "agent-a", nil)
	g.forgetMission("m1")
	if err := g.ensureNoCycle(context.Background(), "m1", "agent-a", []string{"n1"}); err != nil {
		t.Errorf("forgotten mission should not cycle: %v", err)
	}
}
