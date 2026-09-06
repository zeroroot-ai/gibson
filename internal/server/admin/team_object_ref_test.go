// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestTeamRef_AttributesBlameToTheRightSide pins the status codes, which are
// the only thing this wrapper adds over authz.TeamObject.
//
// A bad team_id came off the wire, so it is InvalidArgument and the caller can
// fix it. A bad tenant slug came from requireCallerTenant — the ext-authz
// context, not the request — so reporting it as InvalidArgument would tell a
// caller to fix something they cannot see or influence, and would hide a
// daemon-side invariant break behind a 4xx that nobody pages on.
func TestTeamRef_AttributesBlameToTheRightSide(t *testing.T) {
	for _, tc := range []struct {
		name             string
		tenantID, teamID string
		want             codes.Code
	}{
		{"good", "acme", "ops", codes.OK},
		{"tenant-prefixed form is accepted", "tenant:acme", "ops", codes.OK},
		{"caller's team id carries the separator", "acme", "a/b", codes.InvalidArgument},
		{"caller's team id carries a userset marker", "acme", "ops#member", codes.InvalidArgument},
		{"caller's team id is empty", "acme", "", codes.InvalidArgument},
		{"tenant slug is unusable", "a/b", "ops", codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := teamRef(tc.tenantID, tc.teamID)
			if tc.want == codes.OK {
				if err != nil {
					t.Fatalf("teamRef(%q, %q) = %v, want an object", tc.tenantID, tc.teamID, err)
				}
				if got != "team:acme/ops" {
					t.Errorf("teamRef(%q, %q) = %q, want team:acme/ops", tc.tenantID, tc.teamID, got)
				}
				return
			}
			if err == nil {
				t.Fatalf("teamRef(%q, %q) = %q, want an error", tc.tenantID, tc.teamID, got)
			}
			if code := status.Code(err); code != tc.want {
				t.Errorf("teamRef(%q, %q) returned %s (%v), want %s", tc.tenantID, tc.teamID, code, err, tc.want)
			}
		})
	}
}

// TestTeamRef_ErrorsDoNotLeakTheProbe guards a detail of the implementation: the
// tenant segment is validated by deriving a throwaway object with the team id
// "probe". That word must not reach the caller, or an operator reading the log
// will go looking for a team called "probe".
func TestTeamRef_ErrorsDoNotLeakTheProbe(t *testing.T) {
	_, err := teamRef("a/b", "ops")
	if err == nil {
		t.Fatal("teamRef accepted a tenant slug containing the separator")
	}
	if strings.Contains(err.Error(), "probe") {
		t.Errorf("error mentions the internal probe id: %v", err)
	}
}
