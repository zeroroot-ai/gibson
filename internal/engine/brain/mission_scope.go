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
// dispatched/projected work). LLM-call observations carry no mission id either,
// but they do carry the run_id of the AgentRun that issued the call, and that
// AgentRun is a WorkItem the mission dispatched — so an llm-call is attributed to
// a mission when its run_id names a WorkItem the mission owns (the
// run_id→WorkItem→mission linkage, gibson#1063). A mission-level call with an
// empty run_id (e.g. the Decider's own completion) has no owning agent run and
// attaches to the mission directly. The remaining observation events (host /
// domain / credential / finding / belief / agent-run) carry no mission linkage in
// the event model — they are scope-relative and tenant-ambient — so they are NOT
// part of any single mission's slice. Surfacing a mission's discoveries (the hosts
// and findings it produced) needs a mission→evidence edge the event model does not
// yet record; that is a later rich-frame projection layer (PRD #1059 M2), tracked
// separately. S1 (this file) delivers the isolation guarantee: one mission's
// frame never bleeds another mission's events in.

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
	case LlmCallObserved:
		// run_id→WorkItem→mission linkage (gibson#1063): the call belongs to this
		// mission when the AgentRun that issued it is a WorkItem the mission owns. A
		// mission-level call (empty run_id, e.g. the Decider) attaches directly.
		return e.RunID == "" || owned[e.RunID]
	default:
		// Observation and any other unattributable events are tenant-ambient.
		return false
	}
}
