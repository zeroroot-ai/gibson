// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func row(label, key, app string) map[string]any {
	return map[string]any{"place_label": label, "place_key": key, "application": app}
}

func TestPlacesFromRows(t *testing.T) {
	tests := []struct {
		name string
		rows []map[string]any
		want []Place
	}{
		{"a package that an application reaches", []map[string]any{row("Package", "pkg-1", "shop")},
			[]Place{{PlaceApplication, "shop"}}},
		{"two applications reach one package", []map[string]any{row("Package", "p", "web"), row("Package", "p", "api")},
			[]Place{{PlaceApplication, "api"}, {PlaceApplication, "web"}}},
		{"a host with no application", []map[string]any{row("Host", "h-1", "")},
			[]Place{{PlaceHost, "h-1"}}},
		{"a host that an application reaches is the application", []map[string]any{row("Host", "h-1", "shop")},
			[]Place{{PlaceApplication, "shop"}}},
		{"a package no application reaches has no place", []map[string]any{row("Package", "p", "")}, nil},
		{"a finding that affects nothing", []map[string]any{row("", "", "")}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, placesFromRows(tt.rows))
		})
	}
}

// The two reads share one definition of "an Application reaches a place".
func TestApplicationFindingsCypherUsesTheSharedRoutes(t *testing.T) {
	assert.Contains(t, applicationFindingsCypher, strings.TrimSpace(applicationReachesPlace))
	assert.Contains(t, findingPlacesCypher, strings.TrimSpace(applicationReachesPlace))
}

// The batch read of the places is the read of one finding for each id of the
// list, so the two cannot disagree about an Application (review m9).
func TestFindingPlacesManyCypher_IsTheOneFindingReadForEachID(t *testing.T) {
	assert.Contains(t, findingPlacesManyCypher, "UNWIND $findings AS fid")
	assert.Contains(t, findingPlacesManyCypher, strings.TrimSpace(applicationReachesPlace))
}

// A scan finding is placed at the Image or the Repository where the scan saw it.
// The route walks both to the Application. A Package is never a place, because
// many images share one (gibson#1469).
func TestApplicationReachesPlace_WalksImagesAndRepositories(t *testing.T) {
	for _, route := range []string{
		"(app)-[:HAS_REPOSITORY]->(:Repository)<-[:BUILT_FROM]-(place:Image)",
		"(app)-[:HAS_DEPLOYMENT]->(:Deployment)-[:RUNS]->(place:Image)",
		"(app)-[:HAS_REPOSITORY]->(place)",
	} {
		assert.Contains(t, applicationReachesPlace, route)
	}
	assert.NotContains(t, applicationReachesPlace, "(:Repository)-[:CONTAINS]->(place)",
		"a Repository does not place a Package")
}
