// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

// MetadataCatalogMission is the key of the metadata of a mission record that names
// the checked-in mission that the mission was launched from. Only the two launch
// paths of the catalog write it: the harness origination of an agent and
// DaemonService.RunCatalogMission. A caller cannot set it. Each other create path
// removes the key from the metadata that a caller sends.
const MetadataCatalogMission = "catalog_mission"
