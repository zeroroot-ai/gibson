// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package capname names the reserved, non-component capability-grant bits
// (gibson#1186 slice C, owner decision 2026-08-09).
//
// Every OTHER capability a component holds is derived from an FGA relation on
// a component object — "execute:tool:nmap" exists because an
// agent_principal can_execute component:nmap, and it persists for as long as
// that tuple does, independent of any one registration.
//
// mission:originate and mission:delegate are deliberately NOT that. The owner
// decision requires them to be "a capability-grant bit, not a standing
// tuple" — session-scoped, dying with the grant that carries them, with no
// FGA relation anywhere that could outlive one registration and leak into
// the next. capabilitygrant.RegisterCapabilityGrant is where that is
// enforced: these two names are added to a registration's resolved
// capabilities ONLY when the verified bootstrap credential's own ceiling
// names them, never from FGA resolution. See appendSessionCapabilities in
// internal/platform/capabilitygrant/service.go.
//
// This package exists to break an import cycle: internal/platform/component
// (which enforces the capability check on ComponentServiceServer.
// DelegateToAgent and, eventually, the mission-origination RPCs) and
// internal/platform/capabilitygrant (which mints and persists the grant) both
// need these names, and capabilitygrant already imports component (for the
// registry, via FGABridge) — so component cannot import capabilitygrant
// without a cycle. This leaf package has no dependencies of its own and both
// sides import it.
package capname

// MissionDelegate gates DelegateToAgent: hand a sub-task to another enrolled
// agent WITHIN the caller's current mission. It stays inside that mission's
// existing budget and target scope — no reservation, no widening — which is
// what makes it the lower-trust of the two bits. Most fleet components are
// expected to hold this one.
const MissionDelegate = "mission:delegate"

// MissionOriginate gates the mission-origination RPCs (CreateMission and
// friends): starting a NEW mission, with its own budget reservation against
// the parent's envelope and its own (subset) target scope. Rare, high-trust
// grant — see gibson#1186 slice C for the full rule set. Not yet enforced
// anywhere; defined here so the name is pinned before the handlers land.
const MissionOriginate = "mission:originate"

// reserved is the closed set of names appendSessionCapabilities will ever
// add. Anything else in a credential's ceiling continues to only NARROW the
// FGA-resolved set (capsWithinCeiling) — it can never grant a capability that
// FGA did not already produce.
var reserved = map[string]struct{}{
	MissionDelegate:  {},
	MissionOriginate: {},
}

// IsReserved reports whether name is one of the capability bits this package
// defines.
func IsReserved(name string) bool {
	_, ok := reserved[name]
	return ok
}

// Description returns a human-readable explanation of name for the grant
// record and audit trail. Returns "" for a name IsReserved does not
// recognise.
func Description(name string) string {
	switch name {
	case MissionDelegate:
		return "delegate a sub-task to another enrolled agent within the current mission"
	case MissionOriginate:
		return "originate a new mission with a reserved share of the parent mission's budget"
	default:
		return ""
	}
}
