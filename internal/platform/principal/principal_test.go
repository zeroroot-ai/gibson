// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package principal

import (
	"testing"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestFromIdentity(t *testing.T) {
	cases := map[string]Principal{
		"123456789012345678":             {Kind: User, ID: "123456789012345678"},
		"spiffe://zeroroot.ai/u/1234":    {Kind: User, ID: "zeroroot.ai/u/1234"},
		"user:1234":                      {Kind: User, ID: "1234"},
		"agent_principal:acme/recon":     {Kind: Component, ID: "agent_principal:acme/recon"},
		"tool_principal:acme/nmap":       {Kind: Component, ID: "tool_principal:acme/nmap"},
		"plugin_principal:acme/sentinel": {Kind: Component, ID: "plugin_principal:acme/sentinel"},
	}
	for subject, want := range cases {
		if got := FromIdentity(auth.Identity{Subject: subject}); got != want {
			t.Errorf("%s: got %+v want %+v", subject, got, want)
		}
	}
}

func TestToProtoAndRef(t *testing.T) {
	if ToProto(Principal{}) != nil {
		t.Fatal("the zero principal must render as nil")
	}
	var zero Principal
	if got := zero.Ref(); got != "" {
		t.Fatalf("zero ref: got %q", got)
	}
	if got := (Principal{Kind: User, ID: "42"}).Ref(); got != "user:42" {
		t.Fatalf("ref: got %q", got)
	}
	kinds := map[Kind]commonpb.Principal_Kind{
		User:      commonpb.Principal_KIND_USER,
		Tenant:    commonpb.Principal_KIND_TENANT,
		Component: commonpb.Principal_KIND_COMPONENT,
		Service:   commonpb.Principal_KIND_SERVICE,
	}
	for k, want := range kinds {
		got := ToProto(Principal{Kind: k, ID: "x"})
		if got.GetKind() != want || got.GetId() != "x" {
			t.Errorf("%s: got %v/%q", k, got.GetKind(), got.GetId())
		}
	}
}
