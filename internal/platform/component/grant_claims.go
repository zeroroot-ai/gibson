// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// missionRunClaim is the signed claim that names the mission run of a grant.
const missionRunClaim = "mrid"

// GrantVerifier verifies a capability grant that the daemon minted. The daemon
// verifier answers for its own signing keys only, so a token that a component
// signed itself is refused.
type GrantVerifier interface {
	Verify(ctx context.Context, token string) (sdkcg.Claims, error)
}

// WithGrantVerifier sets the verifier of the task grant that a caller presents
// to bind its work item to its mission.
func (s *ComponentServiceServer) WithGrantVerifier(v GrantVerifier) *ComponentServiceServer {
	s.grantVerifier = v
	return s
}

// callerTaskGrant returns the mission and the mission run that the task grant
// of the caller names. The grant must be the daemon's own task grant: one
// header value, a typ of JWT (a component token has another typ), a signature
// of a daemon key, and the tenant of the request. The run is read from the
// payload of the token whose signature passed.
func (s *ComponentServiceServer) callerTaskGrant(ctx context.Context, tenant string) (mission, run string, err error) {
	deny := func(reason string) (string, string, error) {
		return "", "", status.Error(codes.PermissionDenied, "a delegation from a work item needs a verified task grant: "+reason)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-capability-grant")
	if len(values) != 1 {
		return deny("the request must carry exactly one grant")
	}
	token := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(values[0], "Bearer "), "bearer "))
	parts := strings.Split(token, ".")
	if len(parts) != 3 || tokenHeaderType(parts[0]) != "JWT" {
		return deny("the grant is not a task grant")
	}
	if s.grantVerifier == nil {
		return deny("this daemon cannot verify a grant")
	}
	claims, verifyErr := s.grantVerifier.Verify(ctx, token)
	if verifyErr != nil {
		return deny("the grant did not verify")
	}
	if claims.Tenant.String() != tenant {
		return deny("the grant is for another tenant")
	}
	// Every task grant names its run. A grant with none is not a grant that
	// this daemon minted for a run.
	run = grantPayloadClaim(parts[1], missionRunClaim)
	if run == "" {
		return deny("the grant names no mission run")
	}
	return claims.MissionID, run, nil
}

// tokenHeaderType reads the typ of a token header. It routes only: the
// signature check decides.
func tokenHeaderType(segment string) string {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return ""
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ""
	}
	return header.Typ
}

// grantPayloadClaim reads one string claim from a payload segment of a token
// whose signature passed.
func grantPayloadClaim(segment, name string) string {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	claim, _ := payload[name].(string)
	return claim
}
