// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"strings"
	"testing"
)

func TestBuildPeerPolicy_RefusesAnEdgeListThatCannotBeUsed(t *testing.T) {
	tests := []struct {
		name    string
		edge    string
		gateway string
		wantErr string
	}{
		{"an edge ID that is not a SPIFFE ID", "not-a-spiffe-id", "", "EXT_AUTHZ_ENVOY_SVID: invalid SPIFFE ID"},
		{"an edge list with no ID", " , ,", "", "empty allowlist"},
		{
			"a gateway ID that is not a SPIFFE ID", "spiffe://example.org/platform/envoy", "bad",
			"EXT_AUTHZ_GATEWAY_SVID: invalid SPIFFE ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("EXT_AUTHZ_ENVOY_SVID", tt.edge)
			t.Setenv("EXT_AUTHZ_GATEWAY_SVID", tt.gateway)
			authz, edge, gw, err := buildPeerPolicy()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one that holds %q", err, tt.wantErr)
			}
			if authz != nil || edge != nil || gw != nil {
				t.Errorf("a refused policy returned values: %v %v %v", authz, edge, gw)
			}
		})
	}
}
