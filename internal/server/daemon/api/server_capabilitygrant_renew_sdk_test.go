// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

// The SDK of an agent in pull mode renews its task grant with the current grant
// in x-capability-grant. The same connection also holds the per-RPC token of
// the agent in the authorization header. The renewal reads the grant and no
// other credential, and the new grant keeps the model and the A2A routes.
func TestRenewCapabilityGrant_AcceptsTheGrantThatTheSDKPresents(t *testing.T) {
	claims := renewTestClaims()
	claims.AllowedRPCs = []string{"/v1/responses", "/v1/embeddings", "/"}
	s := newRenewServer(t, liveLookup{live: map[string]bool{"m1": true}})
	s.WithCGRenewal(s.cgMinter, stubVerifier{claims: claims})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer per-rpc-agent-token",
		"x-capability-grant", grantNamingRun("run-1")))
	resp, err := s.RenewCapabilityGrant(ctx, renewRequest())
	if err != nil {
		t.Fatalf("the grant of the SDK must renew: %v", err)
	}
	parts := strings.Split(resp.GetCapabilityGrant(), ".")
	if len(parts) != 3 {
		t.Fatalf("want a compact JWT, got %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode the payload of the new grant: %v", err)
	}
	for _, route := range []string{`"/v1/responses"`, `"/v1/embeddings"`, `"/"`} {
		if !strings.Contains(string(payload), route) {
			t.Errorf("the new grant lost the route %s: %s", route, payload)
		}
	}
}
