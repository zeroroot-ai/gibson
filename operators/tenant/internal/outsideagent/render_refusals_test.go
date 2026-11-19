// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package outsideagent

import (
	"strings"
	"testing"
)

func TestConfigValidate_NeedsTheNamespaceAndTheGatewayName(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"no namespace", Config{GatewayName: "gw"}, "namespace is required"},
		{"no gateway name", Config{Namespace: "ns"}, "gateway name is required"},
		{"complete", Config{Namespace: "ns", GatewayName: "gw"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one that holds %q", err, tt.wantErr)
			}
		})
	}
}

func TestRender_RefusesAURLThatDoesNotParse(t *testing.T) {
	_, err := Render(Agent{Tenant: "acme", Name: "scout", URL: "https://a.example/%zz"}, testConfig())
	if err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("error = %v", err)
	}
}
