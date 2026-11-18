// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// AgentSkillLoad is one load of an Agent Skill by a mission agent (epic
// gibson#1364). The World keeps each load with the agent, the mission and the
// digest that the agent got, so the Timeline shows which content shaped a run.
type AgentSkillLoad struct {
	MissionID string `json:"mission_id"`
	// MissionRunID is the run of the mission of the load. The reducer drops the
	// event when the mission has moved on to another run, so a late load of run 1
	// cannot count for run 2, as for AgentToolCallObserved.
	MissionRunID string `json:"mission_run_id,omitempty"`
	RunID        string `json:"run_id,omitempty"`
	// Agent is the typed FGA principal of the agent. It is empty when the
	// request did not come from an agent principal.
	Agent string `json:"agent,omitempty"`
	// Name is the name of the Agent Skill.
	Name string `json:"name"`
	// Digest is the digest of the OCI image that the agent got.
	Digest string `json:"digest"`
	// File is the reference file of the load. It is empty for a load of the body.
	File string `json:"file,omitempty"`
	// RecordedAtUnixNano is set by the daemon and carried on the event, so a
	// replay gives the same World.
	RecordedAtUnixNano int64 `json:"recorded_at_unix_nano"`
}

// AgentSkillLoaded records that a mission agent loaded an Agent Skill. A refused
// load gives no event.
type AgentSkillLoaded AgentSkillLoad

// Kind identifies this event on the Timeline.
func (AgentSkillLoaded) Kind() string { return "agent_skill.loaded" }

func applyAgentSkillLoaded(w *World, e AgentSkillLoaded) {
	w.agentSkillLoads = append(w.agentSkillLoads, AgentSkillLoad(e))
}

// AgentSkillLoads returns each load of an Agent Skill, in the order of the
// Timeline.
func (w *World) AgentSkillLoads() []AgentSkillLoad {
	return append([]AgentSkillLoad(nil), w.agentSkillLoads...)
}

// AgentSkillLoadSnapshot returns the loads for a snapshot.
func (w *World) AgentSkillLoadSnapshot() []AgentSkillLoad {
	if len(w.agentSkillLoads) == 0 {
		return nil
	}
	return w.AgentSkillLoads()
}
