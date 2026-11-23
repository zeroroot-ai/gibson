// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLookupAction_ExactCatalogToolIDs(t *testing.T) {
	tests := []struct {
		id   string
		want []string
	}{
		{"mcp:okta-response:suspend_user", []string{"ac-2", "ir-4"}},
		{"mcp:okta-response:unsuspend_user", []string{"ac-2", "ir-4"}},
		{"mcp:okta-response:revoke_user_sessions", []string{"ac-12", "ir-4"}},
		{"mcp:entra-id-response:disable_account", []string{"ac-2", "ir-4"}},
		{"mcp:entra-id-response:enable_account", []string{"ac-2", "ir-4"}},
		{"mcp:entra-id-response:revoke_sign_in_sessions", []string{"ac-12", "ir-4"}},
		{"mcp:crowdstrike-response:contain_host", []string{"sc-7", "ir-4"}},
		{"mcp:crowdstrike-response:lift_containment", []string{"sc-7", "ir-4"}},
		{"mcp:defender-endpoint-response:isolate_device", []string{"sc-7", "ir-4"}},
		{"mcp:defender-endpoint-response:release_device", []string{"sc-7", "ir-4"}},
		{"mcp:sentinelone-response:disconnect_from_network", []string{"sc-7", "ir-4"}},
		{"mcp:sentinelone-response:reconnect_to_network", []string{"sc-7", "ir-4"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := lookupAction(tt.id)
			if !ok || !reflect.DeepEqual(got.Controls, tt.want) {
				t.Errorf("lookupAction(%q) = %v, %v, want %v", tt.id, got.Controls, ok, tt.want)
			}
		})
	}
}

func TestLookupAction_UnknownIDMapsToNothing(t *testing.T) {
	for _, id := range []string{
		"", "mcp:crowdstrike:contain_host", "mcp:okta:suspend_user", "mcp:okta-response:delete_user",
		"mcp:crowdstrike-falcon:falcon_search_detections", "okta-response:suspend_user",
	} {
		if a, ok := lookupAction(id); ok {
			t.Errorf("lookupAction(%q) = %+v, want no action", id, a)
		}
	}
}

// Each id must be a tool of the manifest of its connector in the catalog.
func TestResponseActions_EachIDIsAToolOfACatalogManifest(t *testing.T) {
	for _, a := range responseActions {
		connector, tool := splitToolID(a.ToolID)
		if !strings.HasSuffix(connector, "-response") {
			t.Errorf("%s: the connector %q is no response connector", a.ToolID, connector)
		}
		path := filepath.Join("..", "componentcatalog", "manifests", connector+".yaml")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: no manifest for connector %q: %v", a.ToolID, connector, err)
			continue
		}
		var m struct {
			Spec struct {
				Tools map[string]any `yaml:"tools"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if _, ok := m.Spec.Tools[tool]; !ok {
			t.Errorf("%s: the manifest %s names no tool %q", a.ToolID, connector, tool)
		}
	}
}
