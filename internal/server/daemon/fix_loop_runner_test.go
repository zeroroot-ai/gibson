// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

type fakePlacerQuerier struct{ places []component.Place }

func (f fakePlacerQuerier) FindingPlaces(context.Context, string, string) ([]component.Place, error) {
	return f.places, nil
}

func TestApplicationPlacer(t *testing.T) {
	ctx := context.Background()
	host := component.Place{Label: component.PlaceHost, Key: "h1"}
	app := component.Place{Label: component.PlaceApplication, Key: "a1"}
	tests := []struct {
		name    string
		querier any
		want    string
		wantErr bool
	}{
		{"application", fakePlacerQuerier{places: []component.Place{app, host}}, "a1", false},
		{"host only has no application", fakePlacerQuerier{places: []component.Place{host}}, "", false},
		{"no querier is an error", nil, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applicationPlacer{querier: func() any { return tc.querier }}.Application(ctx, "t1", "f1")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}
