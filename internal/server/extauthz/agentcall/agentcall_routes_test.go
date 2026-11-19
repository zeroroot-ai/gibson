// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentcall

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

func TestRouteHeaders(t *testing.T) {
	tests := []struct {
		name string
		bank string
		want []modelcall.RouteHeader
	}{
		{"no bank", "", []modelcall.RouteHeader{
			{Name: modelcall.HeaderRouteTenant, Value: "acme"},
			{Name: HeaderRouteAgent, Value: "scout"},
		}},
		{"with a bank", "bank-9", []modelcall.RouteHeader{
			{Name: modelcall.HeaderRouteTenant, Value: "acme"},
			{Name: HeaderRouteAgent, Value: "scout"},
			{Name: HeaderRouteBank, Value: "bank-9"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RouteHeaders("acme", "scout", tt.bank); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("RouteHeaders = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGrantRoutesListsOnlyTheA2ARoute(t *testing.T) {
	if got := GrantRoutes(); !reflect.DeepEqual(got, []string{RouteA2A}) {
		t.Fatalf("GrantRoutes = %v", got)
	}
}
