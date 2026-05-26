// Spec: unified-identity-and-authorization Requirement 5.8.
//
// RenewCapabilityGrant lets a long-running mission task obtain a
// fresh CG-JWT before its current ≤30-min token expires. The renewal
// path is gated by:
//
//  1. The caller MUST present a valid (signature/exp/aud/iss-good)
//     CG-JWT in the X-Capability-Grant header. ext-authz validates
//     this upstream and forwards the verified-identity headers.
//  2. The CG-JWT's sub claim MUST match the request's agent_id.
//  3. The CG-JWT's mission_id and task_id claims MUST match the
//     request's mission_id and task_id.
//
// Renewal mints a fresh CG-JWT with the same allowed_rpcs and
// tenant scope but a new exp = now + 30min. The fresh token's JTI
// is unique.
//
// Failure modes:
//   - codes.Unauthenticated: no/invalid CG-JWT presented.
//   - codes.PermissionDenied: CG-JWT subject/mission/task mismatch
//     vs the request body.
//   - codes.FailedPrecondition: minter not configured (operator
//     misconfiguration; daemon must be started with --enable-cg-mint).
//   - codes.Internal: minter signing failure.

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"

	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
)

// CGJWTVerifier abstracts the verification path. Implementations
// fetch the daemon's own JWKS (in-process direct-signature check is
// cheaper than a JWKS round-trip when the minter is local). Wired
// at server construction via WithCGJWTVerifier.
type CGJWTVerifier interface {
	Verify(ctx context.Context, token string) (sdkcg.Claims, error)
}

// WithCGRenewal configures the DaemonServer with the CG-JWT minter
// and verifier so the RenewCapabilityGrant RPC is operational.
// Without this configuration the RPC returns FailedPrecondition.
func (s *DaemonServer) WithCGRenewal(minter *capabilitygrant.Minter, verifier CGJWTVerifier) *DaemonServer {
	s.cgMinter = minter
	s.cgVerifier = verifier
	return s
}

// RenewCapabilityGrant implements daemonpb.DaemonServiceServer.
func (s *DaemonServer) RenewCapabilityGrant(ctx context.Context, req *daemonpb.RenewCapabilityGrantRequest) (*daemonpb.RenewCapabilityGrantResponse, error) {
	if s.cgMinter == nil || s.cgVerifier == nil {
		return nil, status.Error(codes.FailedPrecondition, "capability-grant renewal not enabled on this daemon")
	}
	if req == nil || req.AgentId == "" || req.MissionId == "" || req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id, mission_id, task_id all required")
	}

	// Pull the CG-JWT from the request metadata. The header lower-
	// cases per HTTP/2; we accept both forms for caller convenience.
	cgToken := capabilityGrantHeader(ctx)
	if cgToken == "" {
		return nil, status.Error(codes.Unauthenticated, "missing X-Capability-Grant")
	}

	claims, err := s.cgVerifier.Verify(ctx, cgToken)
	if err != nil {
		switch {
		case errors.Is(err, sdkcg.ErrExpired):
			return nil, status.Error(codes.Unauthenticated, "cg-jwt expired; cannot renew an already-expired token (re-dispatch the task)")
		case errors.Is(err, sdkcg.ErrSignature), errors.Is(err, sdkcg.ErrUnknownKey):
			return nil, status.Error(codes.Unauthenticated, "cg-jwt signature invalid")
		case errors.Is(err, sdkcg.ErrClaimsInvalid):
			return nil, status.Error(codes.Unauthenticated, "cg-jwt claims invalid")
		default:
			return nil, status.Error(codes.Unauthenticated, "cg-jwt verification failed")
		}
	}

	// Cross-check the request body against the verified claims.
	if claims.Subject != req.AgentId {
		return nil, status.Error(codes.PermissionDenied, "cg-jwt sub does not match request agent_id")
	}
	if claims.MissionID != req.MissionId {
		return nil, status.Error(codes.PermissionDenied, "cg-jwt mission_id does not match request")
	}
	if claims.TaskID != req.TaskId {
		return nil, status.Error(codes.PermissionDenied, "cg-jwt task_id does not match request")
	}

	// Cross-check that the calling identity's tenant matches the
	// CG-JWT's tenant. Identity is set by the SDK auth interceptor
	// from the headers ext-authz emits.
	identity, idErr := auth.IdentityFromContext(ctx)
	if idErr == nil && identity.Tenant.String() != claims.Tenant.String() {
		return nil, status.Error(codes.PermissionDenied, "context tenant does not match cg-jwt tenant")
	}

	// Mint the renewal. allowed_rpcs and tenant carry over verbatim;
	// JTI/IAT/EXP are fresh. RecipientClass is recovered from the
	// CG-JWT subject, which uses the "component:<kind>:<name>" shape
	// produced by the harness mint path. Required for the Mint deny
	// check (non-plugin-secret-isolation R4) — the renewal MUST inherit
	// the original recipient class so legitimate plugin renewals are
	// not rejected and non-plugin renewals carry the same isolation.
	fresh, err := s.cgMinter.Mint(capabilitygrant.MintRequest{
		Subject:        claims.Subject,
		Tenant:         claims.Tenant.String(),
		MissionID:      claims.MissionID,
		TaskID:         claims.TaskID,
		AllowedRPCs:    claims.AllowedRPCs,
		RecipientClass: recipientClassFromSubject(claims.Subject),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint renewal: %s", err)
	}

	// Decode the newly-minted token's exp claim by re-verifying
	// (cheap; this happens off the hot path of agent traffic).
	freshClaims, vErr := s.cgVerifier.Verify(ctx, fresh)
	var expUnix int64
	if vErr == nil {
		expUnix = freshClaims.ExpiresAt.Unix()
	}

	return &daemonpb.RenewCapabilityGrantResponse{
		CapabilityGrant: fresh,
		ExpiresAtUnix:   expUnix,
	}, nil
}

// capabilityGrantHeader pulls the X-Capability-Grant header out of
// the gRPC metadata, tolerating an optional 'Bearer ' prefix and
// case variants.
func capabilityGrantHeader(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{"x-capability-grant", "x-capability-grant-bin"} {
		vs := md.Get(key)
		for _, v := range vs {
			if v == "" {
				continue
			}
			// Strip optional Bearer prefix.
			if len(v) >= 7 && (v[:7] == "Bearer " || v[:7] == "bearer ") {
				return v[7:]
			}
			return v
		}
	}
	return ""
}

// asHTTPStatus is unused at present but ready for callers that want
// to map the daemon's gRPC errors to HTTP status codes (kept here to
// document the mapping rather than scatter status helpers).
var _ = http.StatusBadRequest

// recipientClassFromSubject extracts the workload class from a CG-JWT
// subject of the form "component:<kind>:<name>" (the shape produced
// by the harness mint path). Returns the empty string for any other
// shape — the empty string fails the Mint deny check closed for
// secret-resolution RPCs by design (non-plugin-secret-isolation R4).
func recipientClassFromSubject(subject string) string {
	const prefix = "component:"
	if !strings.HasPrefix(subject, prefix) {
		return ""
	}
	rest := subject[len(prefix):]
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 {
		return ""
	}
	return rest[:idx]
}
