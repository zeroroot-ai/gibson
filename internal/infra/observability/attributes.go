// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

// Gibson-specific attribute keys for observability
const (

	// Mission-specific attributes
	// GibsonMissionID is the unique identifier for the mission
	GibsonMissionID = "gibson.mission.id"

	// GibsonMissionName is the name of the mission
	GibsonMissionName = "gibson.mission.name"
)

// Gibson span name constants for various operations
const (
	// SpanMissionExecute represents a mission execution operation
	SpanMissionExecute = "gibson.mission.execute"
)
