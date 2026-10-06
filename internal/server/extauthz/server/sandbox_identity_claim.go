// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/fork"
)

// claimForkMethod is the one RPC that a sandbox calls with its identity
// token and no other credential (D80).
const claimForkMethod = harnesspb.HarnessCallbackService_ClaimFork_FullMethodName

// sandboxIdentitySubject is the subject that the edge asserts for a claim.
// The edge cannot verify the token (only the daemon, the owner of the
// sandbox, can ask setec), so the subject names no sandbox.
const sandboxIdentitySubject = "sandbox-identity-claim"

// claimForkResponse decides a ClaimFork call (D80). A fork, or a sandbox
// restored from a snapshot, holds only the identity token that setec gives
// it, and the grant of its source is expired or must not be used. So the
// edge admits ClaimFork with an identity token and no grant, and refuses it
// with a grant or with no token. The daemon verifies the token with setec
// and serves the dispatch only to the sandbox that it started.
//
// The asserted identity has the system tenant and the credential type
// headers.CredentialSandboxIdentity. The daemon refuses that credential on
// every other method.
func claimForkResponse(ctx context.Context, s *EnvoyAuthzServer, httpHeaders map[string]string) *authv3.CheckResponse {
	if extractCapabilityGrant(httpHeaders) != "" {
		extauthzDeniedTotal.WithLabelValues(claimForkMethod).Inc()
		s.log.WarnContext(ctx, "ext-authz: ClaimFork refused: it takes no grant")
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied)
	}
	if strings.TrimSpace(httpHeaders[fork.MetadataSandboxIdentity]) == "" {
		extauthzUnauthenticatedTotal.WithLabelValues(claimForkMethod).Inc()
		return denyResponse(codes.Unauthenticated, typev3.StatusCode_Unauthorized, bodyUnauthenticated)
	}
	id := headers.Identity{
		Subject:        sandboxIdentitySubject,
		Issuer:         headers.IssuerCapabilityGrant,
		CredentialType: headers.CredentialSandboxIdentity,
		Tenant:         auth.SystemTenantString,
	}
	id.IssuedAt = nowUTC()
	extauthzAllowedTotal.WithLabelValues(claimForkMethod).Inc()
	return okResponse(headers.Emit(id))
}
