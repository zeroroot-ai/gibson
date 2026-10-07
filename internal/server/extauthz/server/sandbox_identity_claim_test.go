// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	"github.com/zeroroot-ai/sdk/fork"
)

func claimRequest(hdrs map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
		Http: &authv3.AttributeContext_HttpRequest{Path: claimForkMethod, Headers: hdrs},
	}}}
}

// The edge admits ClaimFork with a sandbox identity token and no grant, and
// asserts the sandbox identity credential (D80).
func TestClaimFork_EdgeAdmitsAnIdentityToken(t *testing.T) {
	srv := buildServerForTenantTests(t, false)
	resp, err := srv.Check(context.Background(), claimRequest(map[string]string{fork.MetadataSandboxIdentity: "tok"}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("code = %d, want OK", resp.GetStatus().GetCode())
	}
	var credential string
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == headers.HeaderCredentialType {
			credential = h.GetHeader().GetValue()
		}
		if h.GetHeader().GetKey() == headers.HeaderTenant {
			t.Fatalf("the edge must not assert a tenant for ClaimFork, got %q", h.GetHeader().GetValue())
		}
	}
	if credential != headers.CredentialSandboxIdentity {
		t.Fatalf("credential type = %q, want %q", credential, headers.CredentialSandboxIdentity)
	}
}

// The edge refuses ClaimFork with a grant, and with no identity token.
func TestClaimFork_EdgeRefusals(t *testing.T) {
	srv := buildServerForTenantTests(t, true)
	cases := map[string]struct {
		hdrs map[string]string
		want int32
	}{
		"grant":    {map[string]string{fork.MetadataSandboxIdentity: "tok", headerCapabilityGrant: "a.b.c"}, int32(codes.PermissionDenied)},
		"no token": {map[string]string{}, int32(codes.Unauthenticated)},
	}
	for name, tc := range cases {
		resp, err := srv.Check(context.Background(), claimRequest(tc.hdrs))
		if err != nil {
			t.Fatalf("%s: Check: %v", name, err)
		}
		if got := resp.GetStatus().GetCode(); got != tc.want {
			t.Errorf("%s: code = %d, want %d", name, got, tc.want)
		}
	}
}
