// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelcall

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestRouteHeaders(t *testing.T) {
	got := RouteHeaders("acme", "openai")
	want := []RouteHeader{
		{Name: HeaderRouteTenant, Value: "acme"},
		{Name: HeaderRouteProvider, Value: "openai"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RouteHeaders = %v, want %v", got, want)
	}
}

// H is a header map.
type H = map[string]string

func TestClaimedRoute(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		wantTenant   string
		wantProvider string
		wantReason   string
	}{
		{"both headers", H{HeaderRouteTenant: " acme ", HeaderRouteProvider: "p1"}, "acme", "p1", ""},
		{"missing tenant", H{HeaderRouteProvider: "p1"}, "", "", "missing_route_header"},
		{"empty tenant", H{HeaderRouteTenant: "  ", HeaderRouteProvider: "p1"}, "", "", "missing_route_header"},
		{"repeated tenant", H{HeaderRouteTenant: "a,b", HeaderRouteProvider: "p1"}, "", "", "repeated_route_header"},
		{"missing provider", H{HeaderRouteTenant: "acme"}, "", "", "missing_route_header"},
		{"repeated provider", H{HeaderRouteTenant: "acme", HeaderRouteProvider: "a,b"}, "", "", "repeated_route_header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, provider, reason := ClaimedRoute(tt.headers)
			if tenant != tt.wantTenant || provider != tt.wantProvider || reason != tt.wantReason {
				t.Fatalf("ClaimedRoute = %q %q %q, want %q %q %q",
					tenant, provider, reason, tt.wantTenant, tt.wantProvider, tt.wantReason)
			}
		})
	}
}

func TestClaimedRouteTenant(t *testing.T) {
	tenant, reason := ClaimedRouteTenant(H{HeaderRouteTenant: "acme"})
	if tenant != "acme" || reason != "" {
		t.Fatalf("got %q %q", tenant, reason)
	}
	if _, reason = ClaimedRouteTenant(map[string]string{}); reason != "missing_route_header" {
		t.Fatalf("reason = %q", reason)
	}
	if _, reason = ClaimedRouteTenant(H{HeaderRouteTenant: "a,b"}); reason != "repeated_route_header" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestPathClassifiers(t *testing.T) {
	tests := []struct {
		path              string
		model, call, edge bool
	}{
		{RouteResponses, true, true, false},
		{RouteEmbeddings, true, true, false},
		{RouteModels, true, false, false},
		{"/v1/other", false, false, false},
		{EdgeModelPrefix + "v1/responses", false, false, true},
		{EdgeAgentPrefix + "a2a", false, false, true},
		{"/gateway/other/x", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsModelPath(tt.path); got != tt.model {
				t.Errorf("IsModelPath = %v", got)
			}
			if got := IsCallRoute(tt.path); got != tt.call {
				t.Errorf("IsCallRoute = %v", got)
			}
			if got := IsEdgeForwardPath(tt.path); got != tt.edge {
				t.Errorf("IsEdgeForwardPath = %v", got)
			}
		})
	}
}

func TestGrantRoutesExcludesModelList(t *testing.T) {
	got := GrantRoutes()
	want := []string{RouteResponses, RouteEmbeddings}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GrantRoutes = %v, want %v", got, want)
	}
}

func TestClaimString(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	tok := "h." + enc([]byte(`{"ini":"user:a","n":5}`)) + ".s"
	tests := []struct {
		name, token, claim, want string
	}{
		{"present", tok, InitiatorClaim, "user:a"},
		{"absent", tok, "missing", ""},
		{"not a string", tok, "n", ""},
		{"not a compact JWT", "abc", InitiatorClaim, ""},
		{"bad base64", "h.!!!.s", InitiatorClaim, ""},
		{"bad json", "h." + enc([]byte("{")) + ".s", InitiatorClaim, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClaimString(tt.token, tt.claim); got != tt.want {
				t.Fatalf("ClaimString = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPurposeRoute(t *testing.T) {
	tests := []struct {
		purpose string
		want    string
		ok      bool
	}{
		{PurposeEmbedding, RouteEmbeddings, true},
		{PurposeChat, RouteResponses, true},
		{PurposeProviderProbe, RouteModels, true},
		{PurposeModelList, RouteModels, true},
		{"admin", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.purpose, func(t *testing.T) {
			got, ok := PurposeRoute(tt.purpose)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("PurposeRoute = %q %v", got, ok)
			}
		})
	}
	if got := DaemonSubject(PurposeChat); got != "component:daemon:chat" {
		t.Fatalf("DaemonSubject = %q", got)
	}
}
