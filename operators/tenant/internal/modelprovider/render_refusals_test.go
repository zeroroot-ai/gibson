// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelprovider

import (
	"strings"
	"testing"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
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

func TestRender_RefusesAProviderWithNoName(t *testing.T) {
	mp := provider("", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderAnthropic})
	_, err := Render(mp, testConfig())
	if err == nil || !strings.Contains(err.Error(), "the name is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestSplitBaseURL_RefusesAURLWithNoHost(t *testing.T) {
	for _, raw := range []string{"https://:8443/x", "https:///x"} {
		if _, _, _, err := splitBaseURL(raw); err == nil || !strings.Contains(err.Error(), "no host") {
			t.Errorf("splitBaseURL(%q) error = %v, want a no host error", raw, err)
		}
	}
}
