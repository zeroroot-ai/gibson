// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"errors"
	"maps"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

// ErrReservedMissionName means that a graph of an agent has the name of a checked-in
// mission.
var ErrReservedMissionName = errors.New(
	"the name of the mission is the name of a checked-in mission. " +
		"Originate that mission with catalog_mission, or choose another name")

// guardOrigination applies the rules of the catalog marker to the metadata of a
// mission that an agent originates. It is the one check of every harness path that
// creates a mission for an agent (gibson#1469):
//
//   - A catalog launch (catalog is the canonical name that the render returned) gets
//     the marker.
//   - Any other mission loses a marker that the caller sent, and it is refused when
//     its name, or the name in its graph, is the name of a checked-in mission.
//
// It returns the metadata to store, a copy that the caller may keep.
func guardOrigination(metadata map[string]any, catalog, name, definitionJSON string) (map[string]any, error) {
	metadata = maps.Clone(metadata) // the caller keeps its own map
	if metadata == nil {
		metadata = map[string]any{}
	}
	if catalog != "" {
		metadata[mission.MetadataCatalogMission] = catalog
		return metadata, nil
	}
	delete(metadata, mission.MetadataCatalogMission)
	if reservedMissionName(name, definitionJSON) {
		return nil, ErrReservedMissionName
	}
	return metadata, nil
}

// reservedMissionName reports whether a graph of a caller, or the name that the
// caller gives it, is the name of a checked-in mission.
func reservedMissionName(name, definitionJSON string) bool {
	if missioncatalog.IsCatalogName(name) {
		return true
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(definitionJSON))
	if err != nil {
		return false // the creation refuses a graph that does not parse
	}
	return missioncatalog.IsCatalogName(def.GetName())
}
