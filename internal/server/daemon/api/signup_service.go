// Package api — signup_service.go implements SignupService.Signup.
//
// Signup is the daemon-side replacement for the IdP-admin half of the
// dashboard's self-serve signup path (E9, gibson#812, ADR-0043/0044). It
// provisions the founding-owner Zitadel human user — create-or-resume the user,
// set the password the customer typed, best-effort send the verification email
// — using the daemon's EXISTING Zitadel admin credential, exactly the ops the
// dashboard signup-bot performed with its privileged PAT
// (enterprise/platform/dashboard/app/actions/signup.ts:createOrResumeZitadelUser).
//
// The handler deliberately does NOT touch Kubernetes and does NOT create the
// Tenant CR: ADR-0023 forbids daemon-side K8s API access. The dashboard keeps
// applying the Tenant CR (ADR-0044), keyed by the slug this handler returns;
// the gibson-tenant-operator then reconciles it into the per-tenant Zitadel org
// and the rest of the provisioning chain (gibson#803/#805). Moving the Tenant
// CR write off the dashboard is dashboard#813, not this slice.
//
// Authorization: Signup is UNAUTHENTICATED (pre-tenant, attempt_id-keyed) per
// the proto annotation — there is no principal to FGA-check, exactly like
// UserService.SetSignupProgress.
package api

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// slugNonAllowed matches every run of characters that are not lowercase
// alphanumerics or hyphens; runs collapse to a single hyphen. This mirrors the
// dashboard's slugify (src/lib/signup/slug.ts) so the slug the daemon returns
// is byte-identical to the one the dashboard computes and stamps on the Tenant
// CR. Keep these two in sync.
var slugNonAllowed = regexp.MustCompile(`[^a-z0-9-]+`)

// signupSlugify derives a tenant slug from a workspace display name, mirroring
// the dashboard's slugify exactly:
//
//	lowercase → replace non [a-z0-9-] with "-" → collapse runs of "-" →
//	trim leading/trailing "-" → cap at 63 chars.
func signupSlugify(s string) string {
	s = strings.ToLower(s)
	s = slugNonAllowed.ReplaceAllString(s, "-")
	// Collapse any remaining multi-hyphen runs (the regex already collapses
	// non-allowed runs, but pre-existing hyphens in the input can still
	// adjoin).
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = s[:63]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// Signup implements SignupServiceServer.
//
// It is unauthenticated and idempotent on owner email: a retry resumes the
// existing owner user (resetting its password) rather than failing.
//
// The handler is gated on the signup seam policy (SIGNUP_SELF_SERVE knob,
// deploy ADR-0006, gibson#1088). When the policy is not PolicySelfServe (knob
// absent = self-hosted fail-safe = admin-only), it returns codes.PermissionDenied
// with a clear message directing the caller to use AdminProvisionTenant instead.
// The default zero-value policy fails closed (same as PolicyAdminOnly), so a
// misconfigured SaaS deployment cannot accidentally open self-serve on a
// self-hosted install.
func (s *DaemonServer) Signup(ctx context.Context, req *tenantv1.SignupRequest) (*tenantv1.SignupResponse, error) {
	// ---- signup seam gate (deploy ADR-0006) ----
	// Only proceed when the self-serve profile is explicitly active.
	// The zero value "" is treated as PolicyAdminOnly (fail-closed).
	if s.signupPolicy != signup.PolicySelfServe {
		return nil, status.Errorf(codes.PermissionDenied,
			"self-serve signup is not available on this deployment; contact your administrator to provision a tenant via AdminProvisionTenant")
	}

	// ---- validate ----
	if req.GetAttemptId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "attempt_id is required")
	}
	if !isUUID(req.GetAttemptId()) {
		return nil, status.Errorf(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	if req.GetOwnerEmail() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "owner_email is required")
	}
	if req.GetWorkspaceName() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "workspace_name is required")
	}
	if req.GetTier() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tier is required")
	}
	if req.GetPassword() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "password is required")
	}

	slug := signupSlugify(req.GetWorkspaceName())
	if slug == "" {
		return nil, status.Errorf(codes.InvalidArgument, "workspace_name does not yield a valid tenant slug")
	}

	if s.idpAdminClient == nil {
		return nil, status.Errorf(codes.Unavailable, "identity provider not configured")
	}

	// ---- provision the founding-owner Zitadel user ----
	// OrgID is left empty: the owner user is provisioned in the admin client's
	// default (platform) org. Per-tenant org membership is added later by the
	// operator once the tenant's org exists (TenantIdentity, gibson#803).
	result, err := s.idpAdminClient.CreateHumanUser(ctx, idp.CreateHumanUserRequest{
		Email:      req.GetOwnerEmail(),
		GivenName:  req.GetOwnerFirstName(),
		FamilyName: req.GetOwnerLastName(),
		Password:   req.GetPassword(),
		// Mark verified at create-time, mirroring the dashboard signup default:
		// Zitadel keeps unverified users in STATE_INITIAL which blocks
		// password sign-in. The user just typed the password and submitted; a
		// best-effort verification email below handles real ownership
		// confirmation without gating login on it.
		EmailVerified: true,
	})
	if err != nil {
		// NEVER log req.Password. Log only the attempt id and the sanitized
		// idp error (the idp layer already strips credential-bearing detail).
		s.logger.ErrorContext(ctx, "Signup: provision owner user failed",
			"attempt_id", req.GetAttemptId(),
			"error", err.Error(),
		)
		if errors.Is(err, idp.ErrUnreachable) {
			return nil, status.Errorf(codes.Unavailable, "identity provider unreachable")
		}
		// All other failures — including idp.ErrPermission (the daemon's admin
		// credential lacks the rights, an operator misconfiguration, not a
		// caller error) — map to Internal with a sanitized message.
		return nil, status.Errorf(codes.Internal, "failed to provision owner user")
	}

	// ---- best-effort verification email ----
	// Skipped implicitly when the user was created already-verified: Zitadel has
	// no pending code and the resend returns an error, which we treat as
	// non-fatal (matches the dashboard's conditional skip). We still call it so
	// that a future SMTP-enabled / unverified-at-create flow re-enables the mail
	// automatically; any error is logged and swallowed.
	if verr := s.idpAdminClient.SendVerificationEmail(ctx, result.UserID); verr != nil {
		s.logger.InfoContext(ctx, "Signup: verification email not sent (non-fatal)",
			"attempt_id", req.GetAttemptId(),
			"error", verr.Error(),
		)
	}

	// ---- enqueue the tenant for operator-pull provisioning ----
	// Operator-pull tenant provisioning (E9, gibson#948, enables dashboard#813):
	// instead of the dashboard creating the Tenant CR, the daemon records the
	// tenant in its pending-provisioning queue (platform Postgres). The
	// tenant-operator drains the queue and creates the Tenant CR — the daemon
	// never touches Kubernetes (ADR-0023). Idempotent on tenant_id (the slug),
	// matching the owner-provisioning resume above. Failure to enqueue is
	// non-fatal to the owner-provisioning response but is logged loudly: an
	// enqueue miss strands the tenant un-provisioned, so it must be visible.
	if enqueued, eerr := s.enqueuePendingTenantProvisioning(ctx, &daemonoperatorv1.PendingTenant{
		TenantId:         slug,
		OwnerUserId:      result.UserID,
		OwnerEmail:       req.GetOwnerEmail(),
		WorkspaceName:    req.GetWorkspaceName(),
		Tier:             req.GetTier(),
		StripeCustomerId: req.GetStripeCustomerId(),
	}); eerr != nil {
		s.logger.ErrorContext(ctx, "Signup: enqueue pending tenant provisioning failed",
			"attempt_id", req.GetAttemptId(),
			"tenant_id", slug,
			"error", eerr.Error(),
		)
	} else {
		s.logger.InfoContext(ctx, "Signup: tenant enqueued for operator-pull provisioning",
			"attempt_id", req.GetAttemptId(),
			"tenant_id", slug,
			"newly_enqueued", enqueued,
		)
	}

	return &tenantv1.SignupResponse{
		TenantId:       slug,
		AlreadyExisted: result.AlreadyExisted,
		OwnerUserId:    result.UserID,
	}, nil
}
