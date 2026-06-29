package brain

// mission_scope.go scopes a fold to a single mission run (gibson#1060, PRD #1059).
//
// The World is a fold of the tenant Timeline (ADR-0001: World == fold(Timeline)).
// To replay one mission run in isolation we fold not the whole Timeline but the
// mission's *slice* of it — the sub-sequence of events attributable to that
// mission, in Timeline order. Folding a slice is still a pure events→world fold;
// it just starts from a filtered log, so no new state and no new event kinds are
// introduced (the read-only projection invariant holds).
//
// Attribution. An event belongs to a mission when it names the mission directly
// (mission-lifecycle, dispatch, decision and token events all carry the mission
// id) or references a WorkItem the mission owns (retry / completion / condition
// events carry only a work id, resolved to the owning mission via the mission's
// dispatched/projected work).
//
// Evidence (host / finding / llm-call). Discovered evidence is attributed by the
// mission-evidence edge: each such observation now carries the MissionID of the
// mission whose work produced it (gibson#1075), stamped at ingest from the agent
// callback / mission-event context (and, for a surprise→Finding promotion,
// inherited from the source host). So a host, finding or llm-call is in the
// mission's slice when its MissionID names the mission — one consistent, working
// edge across all three. This replaces the earlier run_id→WorkItem→mission attempt
// for llm-calls (gibson#1063), which never connected in practice: the production
// ExecuteLLM path left run_id empty, so the old `run_id==""` fallback attached
// every call to *every* mission (cross-mission bleed). Direct MissionID matching
// fixes that; an evidence event with no mission context (empty MissionID — e.g. a
// component-path finding or an ExecuteLLM call that carries none) attaches to no
// mission and stays tenant-ambient (propagation of that context is follow-up
// gibson#1078). The remaining observation events (domain / credential / account /
// subdomain / belief / agent-run) still carry no mission linkage and remain
// tenant-ambient.
//
// Folding a slice is still a pure events→world fold over a filtered log; an empty
// MissionID match-by-equality never bleeds into a named mission, and the
// tenant-wide fold (empty missionID) is unchanged.

// MissionSlice returns the sub-sequence of events attributable to missionID, in
// Timeline order. An empty missionID returns a copy of the whole slice (the
// tenant-wide fold is unchanged). The result is deterministic, so folding it is
// a stable replay frame.
func MissionSlice(events []Event, missionID string) []Event {
	if missionID == "" {
		return append([]Event(nil), events...)
	}

	// Pass 1: discover the WorkItem ids this mission owns, so events that name
	// only a work id (retry / completion / condition) can be attributed.
	owned := make(map[string]bool)
	for _, ev := range events {
		switch e := ev.(type) {
		case MissionProjected:
			if e.ID == missionID {
				for _, n := range e.Nodes {
					owned[n.ID] = true
				}
			}
		case WorkDispatched:
			if e.MissionID == missionID {
				owned[e.ID] = true
			}
		}
	}

	// Pass 2: collect the attributable events in Timeline order.
	out := make([]Event, 0, len(events))
	for _, ev := range events {
		if eventInMission(ev, missionID, owned) {
			out = append(out, ev)
		}
	}
	return out
}

// eventInMission reports whether ev is attributable to missionID, given the set
// of WorkItem ids the mission owns (from MissionSlice's first pass).
func eventInMission(ev Event, missionID string, owned map[string]bool) bool {
	switch e := ev.(type) {
	case MissionStarted:
		return e.ID == missionID
	case MissionProjected:
		return e.ID == missionID
	case MissionPauseRequested:
		return e.ID == missionID
	case MissionResumed:
		return e.ID == missionID
	case MissionDone:
		return e.ID == missionID
	case WorkDispatched:
		return e.MissionID == missionID
	case WorkRetried:
		return owned[e.ID]
	case WorkCompleted:
		return owned[e.ID]
	case ConditionResolved:
		return owned[e.ID]
	case DecisionRequested:
		return e.MissionID == missionID
	case DecisionCompleted:
		return e.MissionID == missionID
	case TokenUsed:
		return e.MissionID == missionID
	case HostObserved:
		// Mission-evidence edge (gibson#1075): the host is in the slice when the
		// mission whose work discovered it is this mission. Empty MissionID =
		// tenant-ambient (no bleed into a named mission).
		return e.MissionID != "" && e.MissionID == missionID
	case FindingRaised:
		// Mission-evidence edge (gibson#1075): agent/decider findings carry the
		// mission id at ingest; a surprise→Finding promotion inherits it from the
		// source host. Empty MissionID = tenant-ambient.
		return e.MissionID != "" && e.MissionID == missionID
	case LlmCallObserved:
		// Mission-evidence edge (gibson#1075): one consistent edge with hosts and
		// findings. Empty MissionID (e.g. an ExecuteLLM call with no mission context)
		// = tenant-ambient — never attaches to a mission frame, fixing the prior
		// run_id-based cross-mission bleed (gibson#1063).
		return e.MissionID != "" && e.MissionID == missionID
	default:
		// Any other unattributable observation is tenant-ambient.
		return false
	}
}
