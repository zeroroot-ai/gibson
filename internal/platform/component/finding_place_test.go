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
