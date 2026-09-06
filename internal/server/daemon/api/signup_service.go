// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — signup_service.go implements SignupService.
//
// The service enforces one rule: nothing persistent, billable or tenant-visible
// is created for an email address until the person signing up has proven they
// control it.
//
// Three handlers, in order:
//
//	RequestEmailVerification — writes one expiring verification row and sends
//	                           one email. No identity, no billing object, no
//	                           tenant. The response is empty and identical for
//	                           every accepted request.
//	RedeemEmailVerification  — atomically exchanges the emailed token for a
//	                           short completion session. Single-use.
//	Signup                   — creates the Zitadel human user and enqueues the
//	                           tenant. Requires a live session; reads the email,
//	                           workspace and tier from the verification row, not
//	                           from the caller.
//
// Two behaviours that used to live here and no longer do:
//
//   - Signup no longer resumes an existing user. A conflicting address returns
//     AlreadyExists and no credential is written. The previous shape reset the
//     existing account's password to whatever the form carried.
//   - The founding owner is no longer created EmailVerified on the strength of
//     a form submission. It is created verified because the daemon verified it,
//     one step earlier, with a token it sent to the address itself.
//
// The daemon still performs NO Kubernetes write (ADR-0023): provisioning is
// enqueued in platform Postgres and the tenant-operator drains the queue.
//
// Authorization: all handlers are UNAUTHENTICATED per the proto annotation —
// they run before any tenant or membership exists. The emailed token, and then
// the session derived from it, are the capabilities.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/plans"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
)

// slugNonAllowed matches every run of characters that are not lowercase
// alphanumerics or hyphens; runs collapse to a single hyphen. This mirrors the
// dashboard's slugify (src/lib/signup/slug.ts) so the slug the daemon returns
// is byte-identical to the one the dashboard computes. Keep these two in sync.
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

// signupEmailPattern is a deliberately loose shape check. Its job is to reject
// obvious nonsense before a send is attempted, not to decide deliverability —
// that is the mail transport's answer, and it is the same answer for an address
// that exists and one that does not.
var signupEmailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$`)

// redeemDenied is the single response every failed redemption returns.
//
// One error value, constructed once, so no code path can accidentally
// differentiate unknown / expired / already-used / malformed by message,
// details or code. Any difference here is an oracle for which signups and
// which tokens exist.
func redeemDenied() error {
	return status.Error(codes.PermissionDenied, "this link is no longer valid; request a new one")
}

// selfServeGate rejects the request unless the deployment explicitly runs the
// self-serve profile. The zero-value policy is treated as admin-only, so a
// misconfigured install fails closed rather than opening public signup.
func (s *DaemonServer) selfServeGate() error {
	if s.signupPolicy != signup.PolicySelfServe {
		return status.Error(codes.PermissionDenied,
			"self-serve signup is not available on this deployment; contact your administrator to provision a tenant via AdminProvisionTenant")
	}
	return nil
}

// stripeCustomerIDPattern is the shape of a Stripe customer identifier.
//
// A shape check is not an ownership check — the store's statement is what
// binds the id to the session, in both directions. This is the cheap half:
// it keeps arbitrary caller text out of a column that flows on to the
// provisioning row and the tenant-status row, and it is answerable from the
// request alone, so it costs no database round-trip.
var stripeCustomerIDPattern = regexp.MustCompile(`^cus_[A-Za-z0-9]{1,64}$`)

// isStripeCustomerID reports whether s has the shape of a Stripe customer id.
func isStripeCustomerID(s string) bool { return stripeCustomerIDPattern.MatchString(s) }

// hashClientIP reduces an IP to a hash before it is stored. The row it lands on
// is created before anyone has consented to anything and may describe someone
// who never asked for it.
func hashClientIP(ip string) string {
	if ip == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])
}

// RequestEmailVerification implements SignupServiceServer.
//
// Side effects, in full: rate-limit counters, one signup_verification row, one
// outbound email. Nothing else. No Zitadel user, no billing customer, no
// provisioning queue entry, no tenant slug claim.
//
// The response is empty and identical for every accepted request. See the proto
// for why that is the contract rather than an omission.
func (s *DaemonServer) RequestEmailVerification(ctx context.Context, req *tenantv1.RequestEmailVerificationRequest) (*tenantv1.RequestEmailVerificationResponse, error) {
	if err := s.selfServeGate(); err != nil {
		return nil, err
	}

	email, err := validateRequestEmailVerification(req)
	if err != nil {
		return nil, err
	}

	// ---- rate limits (fail-closed) ----
	// client_ip is a caller claim the daemon cannot verify; normalizing it is
	// what keeps it a bucket key rather than arbitrary text. See the
	// signup_rate_limit.go package comment for what it is and is not worth.
	clientIP := normalizeSignupClientIP(req.GetClientIp())
	if err := s.checkSignupLimits(ctx, requestVerificationLimits(email, clientIP)...); err != nil {
		return nil, err
	}

	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	if s.signupMailer == nil {
		// No transport means no proof of mailbox control is obtainable, and a
		// signup that cannot obtain proof must not proceed to provisioning.
		// Refuse rather than fall back to an unverified path.
		//
		// FailedPrecondition, not Unavailable: this is a deployment
		// misconfiguration the daemon already warned about at startup
		// (resolveSignupMailer, gibson#1228 / PR #1228), not a transient
		// condition worth retrying. The daemon itself boots regardless of mail
		// configuration; this is where the requirement is enforced instead —
		// per call, before any row is written, so a broken transport can never
		// leave a token that was never delivered.
		return nil, status.Error(codes.FailedPrecondition,
			"self-serve signup unavailable: no delivering email transport configured")
	}

	// ---- resend cooldown ----
	if err := s.checkSignupResendCooldown(ctx, email); err != nil {
		return nil, err
	}

	// ---- write the verification row ----
	row, rawToken, err := s.signupVerifications.Issue(ctx, IssueParams{
		AttemptID:      req.GetAttemptId(),
		Email:          email,
		WorkspaceName:  req.GetWorkspaceName(),
		Tier:           req.GetTier(),
		OwnerFirstName: req.GetOwnerFirstName(),
		OwnerLastName:  req.GetOwnerLastName(),
		ClientIPHash:   hashClientIP(clientIP),
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "RequestEmailVerification: issue failed",
			"attempt_id", req.GetAttemptId(), "error", err.Error())
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}

	if err := s.sendVerificationOrCollisionNotice(ctx, req, email, row, rawToken); err != nil {
		return nil, err
	}

	return &tenantv1.RequestEmailVerificationResponse{}, nil
}

// validateRequestEmailVerification decides every rejection that is answerable
// from the request alone, so none of them leak whether the address is
// registered. Returns the normalized email on success.
func validateRequestEmailVerification(req *tenantv1.RequestEmailVerificationRequest) (string, error) {
	if req.GetAttemptId() == "" || !isUUID(req.GetAttemptId()) {
		return "", status.Error(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	email := NormalizeSignupEmail(req.GetOwnerEmail())
	if email == "" || !signupEmailPattern.MatchString(email) {
		return "", status.Error(codes.InvalidArgument, "owner_email must be a valid email address")
	}
	if strings.TrimSpace(req.GetWorkspaceName()) == "" {
		return "", status.Error(codes.InvalidArgument, "workspace_name is required")
	}
	if strings.TrimSpace(req.GetTier()) == "" {
		return "", status.Error(codes.InvalidArgument, "tier is required")
	}
	if signupSlugify(req.GetWorkspaceName()) == "" {
		return "", status.Error(codes.InvalidArgument, "workspace_name does not yield a valid tenant slug")
	}
	return email, nil
}

// checkSignupResendCooldown refuses a resend that arrives too soon after the
// last one for this address.
func (s *DaemonServer) checkSignupResendCooldown(ctx context.Context, email string) error {
	last, ok, err := s.signupVerifications.LastSentAt(ctx, email)
	if err != nil {
		s.logger.ErrorContext(ctx, "RequestEmailVerification: cooldown lookup failed", "error", err.Error())
		return status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	if ok && s.signupNow().Sub(last) < SignupResendCooldown {
		// ResourceExhausted, the same code the rate limiter returns, so a
		// cooldown hit is indistinguishable from a limit hit. It does still
		// reveal that SOME request was recently made for this address — which
		// is why the per-email budget above is small enough that probing the
		// cooldown costs an attacker their whole allowance for that address.
		return status.Error(codes.ResourceExhausted, "too many signup requests; please try again later")
	}
	return nil
}

// existingSignupUserID looks up whether email already has an IdP account. The
// lookup happens AFTER the verification row is written and only selects which
// message template to send; both branches perform one lookup and one send, so
// the two paths cost the same and return the same thing.
func (s *DaemonServer) existingSignupUserID(ctx context.Context, email string) string {
	if s.idpAdminClient == nil {
		return ""
	}
	switch id, lerr := s.idpAdminClient.FindUserIDByEmail(ctx, email); {
	case lerr == nil:
		return id
	case errors.Is(lerr, idp.ErrNotFound):
		// No account — verification link.
		return ""
	default:
		// A directory that cannot answer is not a reason to disclose anything
		// or to skip the send; treat it as "no account" and send the
		// verification link. The completion step re-checks and fails closed
		// with AlreadyExists if the address turns out to be taken.
		s.logger.WarnContext(ctx, "RequestEmailVerification: directory lookup failed; sending verification",
			"error", lerr.Error())
		return ""
	}
}

// sendVerificationOrCollisionNotice sends the one message the request earns —
// a verification link for a fresh address, an account-exists notice (no token)
// for a registered one — and enforces that a send failure is fatal rather than
// swallowed: telling someone to check an inbox for a message that was never
// sent leaves them waiting on nothing, and hides a broken transport for as
// long as nobody complains. Enumeration-safe: both branches send exactly one
// message, so both branches can fail this way alike.
func (s *DaemonServer) sendVerificationOrCollisionNotice(ctx context.Context, req *tenantv1.RequestEmailVerificationRequest, email string, row SignupVerification, rawToken string) error {
	existingUserID := s.existingSignupUserID(ctx, email)

	var sendErr error
	if existingUserID != "" {
		// The address already has an account. Send a notice with NO token and
		// NO continue link, and retire the row immediately — the token it
		// holds must never be redeemable, because it was never delivered.
		//
		// This is the only place the duplicate-address fact is disclosed, and
		// it is disclosed to the mailbox that owns the address.
		sendErr = s.signupMailer.SendAccountExists(ctx, mailer.AccountExistsEmail{
			To:            email,
			SignInURL:     s.signupSignInURL(),
			PasswordReset: s.signupPasswordResetURL(),
		})
		if cerr := s.signupVerifications.MarkConsumedByID(ctx, row.ID); cerr != nil {
			s.logger.ErrorContext(ctx, "RequestEmailVerification: retiring collision row failed",
				"error", cerr.Error())
		}
	} else {
		sendErr = s.signupMailer.SendSignupVerification(ctx, mailer.VerificationEmail{
			To:             email,
			ContinueURL:    s.signupContinueURL(rawToken),
			ExpiresInHours: int(SignupVerificationTTL.Hours()),
		})
	}

	if sendErr != nil {
		if merr := s.signupVerifications.MarkSendFailed(ctx, row.ID); merr != nil {
			s.logger.ErrorContext(ctx, "RequestEmailVerification: marking send_failed failed", "error", merr.Error())
		}
		s.logger.ErrorContext(ctx, "RequestEmailVerification: send failed",
			"attempt_id", req.GetAttemptId(), "error", sendErr.Error())
		return status.Error(codes.Unavailable, "we couldn't send the verification email; please try again")
	}

	if err := s.signupVerifications.MarkSent(ctx, row.ID); err != nil {
		// The mail is already gone; failing the request now would tell the
		// caller to retry a send that succeeded. Log and accept.
		s.logger.ErrorContext(ctx, "RequestEmailVerification: marking sent failed", "error", err.Error())
	}
	return nil
}

// RedeemEmailVerification implements SignupServiceServer.
//
// One atomic compare-and-set in the store decides the outcome. Every failure
// returns redeemDenied() — the same code and the same message — so redemption
// cannot be used to probe which tokens or signups exist.
func (s *DaemonServer) RedeemEmailVerification(ctx context.Context, req *tenantv1.RedeemEmailVerificationRequest) (*tenantv1.RedeemEmailVerificationResponse, error) {
	if err := s.selfServeGate(); err != nil {
		return nil, err
	}
	if err := s.checkSignupLimits(ctx, redeemLimits(normalizeSignupClientIP(req.GetClientIp()))...); err != nil {
		return nil, err
	}
	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}

	row, session, err := s.signupVerifications.RedeemToken(ctx, req.GetToken())
	switch {
	case errors.Is(err, ErrSignupVerificationNotFound):
		return nil, redeemDenied()
	case err != nil:
		s.logger.ErrorContext(ctx, "RedeemEmailVerification: redeem failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}

	return &tenantv1.RedeemEmailVerificationResponse{
		VerifiedSessionToken: session,
		AttemptId:            row.AttemptID,
		OwnerEmail:           row.Email,
		WorkspaceName:        row.WorkspaceName,
		Tier:                 row.Tier,
	}, nil
}

// AttachSignupCustomer implements SignupServiceServer.
//
// Records the billing customer against the verified session so that completion
// reads the customer id from the daemon's own row rather than from the client.
func (s *DaemonServer) AttachSignupCustomer(ctx context.Context, req *tenantv1.AttachSignupCustomerRequest) (*tenantv1.AttachSignupCustomerResponse, error) {
	if err := s.selfServeGate(); err != nil {
		return nil, err
	}
	if err := s.checkSignupLimits(ctx, attachCustomerLimits(normalizeSignupClientIP(req.GetClientIp()))...); err != nil {
		return nil, err
	}
	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	if req.GetStripeCustomerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "stripe_customer_id is required")
	}
	if !isStripeCustomerID(req.GetStripeCustomerId()) {
		return nil, status.Error(codes.InvalidArgument, "stripe_customer_id is not a customer identifier")
	}
	switch err := s.signupVerifications.AttachStripeCustomer(ctx, req.GetVerifiedSessionToken(), req.GetStripeCustomerId()); {
	case errors.Is(err, ErrSignupVerificationNotFound):
		return nil, redeemDenied()
	case err != nil:
		s.logger.ErrorContext(ctx, "AttachSignupCustomer: attach failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	return &tenantv1.AttachSignupCustomerResponse{}, nil
}

// Signup implements SignupServiceServer.
//
// This is the only path to provisioning, and it does not run without a live
// verified session. Everything about the tenant — owner address, workspace
// name, tier, profile, billing customer — is read from the verification row the
// session resolves to; the request carries none of it. A caller who redeemed a
// token for one address therefore cannot provision a tenant for another.
func (s *DaemonServer) Signup(ctx context.Context, req *tenantv1.SignupRequest) (*tenantv1.SignupResponse, error) {
	if err := s.selfServeGate(); err != nil {
		return nil, err
	}

	// ---- validate ----
	if req.GetAttemptId() == "" || !isUUID(req.GetAttemptId()) {
		return nil, status.Error(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetVerifiedSessionToken() == "" {
		// Same denial as an expired or spent session: an absent session is not
		// a different kind of failure, it is the same "you have not proven
		// this address" answer.
		return nil, redeemDenied()
	}

	// ---- rate-limit gate ----
	// Cheapest and most abusable check first: reject before touching the
	// verification store, the identity provider or the plan set. Runs ahead
	// of every other gate and every side effect below.
	if err := s.checkSignupLimits(ctx, completeLimits(normalizeSignupClientIP(req.GetClientIp()))...); err != nil {
		return nil, err
	}

	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	if s.idpAdminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity provider not configured")
	}

	// ---- spend one completion attempt against the verified session ----
	// The claim is atomic and capped, so a completion that keeps failing (a
	// declined card, a transient IdP error) cannot be looped indefinitely
	// against one proof.
	row, err := s.signupVerifications.ClaimCompletion(ctx, req.GetVerifiedSessionToken())
	switch {
	case errors.Is(err, ErrSignupVerificationNotFound):
		return nil, redeemDenied()
	case err != nil:
		s.logger.ErrorContext(ctx, "Signup: claim completion failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	if row.AttemptID != req.GetAttemptId() {
		// The session belongs to a different signup attempt. Deny with the
		// same message as every other session failure.
		return nil, redeemDenied()
	}

	slug := signupSlugify(row.WorkspaceName)
	if slug == "" {
		// The workspace name was validated at request time, so this means the
		// row is corrupt rather than the caller being wrong.
		s.logger.ErrorContext(ctx, "Signup: verification row yields no slug",
			"attempt_id", req.GetAttemptId())
		return nil, status.Error(codes.Internal, "failed to complete signup")
	}

	// ---- plan gate ----
	// SignupRequest carries neither tier nor billing-customer id — both are
	// read from the verification row, exactly so a caller cannot self-select
	// a paid tier by putting one in the request. row.Tier reaches the
	// operator through the pending-provisioning queue, where it sizes the
	// per-tenant data plane and binds the Stripe product, so resolve it
	// against the canonical plan set before creating any identity or
	// provisioning state. See plan gate rationale in internal/platform/plans.
	plan, err := s.resolveSignupPlan(row.Tier, row.StripeCustomerID)
	if err != nil {
		s.logger.WarnContext(ctx, "Signup: plan gate refused request",
			"attempt_id", req.GetAttemptId(),
			"requested_tier", row.Tier,
			"error", err.Error(),
		)
		return nil, err
	}

	// ---- create the founding-owner user ----
	// EmailVerified is true because the daemon verified it: this call is only
	// reachable after the address redeemed a token the daemon sent to it. The
	// claim made to the IdP is one we can back.
	result, err := s.idpAdminClient.CreateHumanUser(ctx, idp.CreateHumanUserRequest{
		Email:         row.Email,
		GivenName:     row.OwnerFirstName,
		FamilyName:    row.OwnerLastName,
		Password:      req.GetPassword(),
		EmailVerified: true,
	})
	if err != nil {
		// NEVER log req.Password. Log the attempt id and the sanitized idp
		// error only.
		s.logger.ErrorContext(ctx, "Signup: provision owner user failed",
			"attempt_id", req.GetAttemptId(),
			"error", err.Error(),
		)
		switch {
		case errors.Is(err, idp.ErrAlreadyExists):
			// The address acquired an account between the verification email
			// and this call. Report it and stop — no password is written to
			// that account, by this path or any other.
			//
			// Disclosing it here is safe in a way it would not be at request
			// time: this caller has already proven control of the mailbox.
			return nil, status.Error(codes.AlreadyExists,
				"an account already exists for this email address; please sign in instead")
		case errors.Is(err, idp.ErrUnreachable):
			return nil, status.Error(codes.Unavailable, "identity provider unreachable")
		default:
			// Including idp.ErrPermission — an operator misconfiguration, not
			// a caller error. Sanitized message either way.
			return nil, status.Error(codes.Internal, "failed to provision owner user")
		}
	}

	// ---- enqueue the tenant for operator-pull provisioning ----
	// Operator-pull tenant provisioning (E9, gibson#948, enables dashboard#813):
	// instead of the dashboard creating the Tenant CR, the daemon records the
	// tenant in its pending-provisioning queue (platform Postgres). The
	// tenant-operator drains the queue and creates the Tenant CR — the daemon
	// never touches Kubernetes (ADR-0023). Idempotent on tenant_id (the slug),
	// matching the owner-provisioning resume above.
	//
	// FATAL on failure. The verified session is about to be consumed, so a
	// silent enqueue miss would strand a tenant that has an owner identity, no
	// provisioning record and no proof left to retry with. Better to fail the
	// call and leave the session spendable (the attempt cap bounds retries).
	if _, eerr := s.enqueuePendingTenantProvisioning(ctx, &daemonoperatorv1.PendingTenant{
		TenantId:      slug,
		OwnerUserId:   result.UserID,
		OwnerEmail:    row.Email,
		WorkspaceName: row.WorkspaceName,
		// Enqueue the RESOLVED canonical plan id, not the raw verification-row
		// string, so nothing downstream sees an id the plan gate did not accept.
		Tier:             plan.ID,
		StripeCustomerId: row.StripeCustomerID,
	}); eerr != nil {
		s.logger.ErrorContext(ctx, "Signup: enqueue pending tenant provisioning failed",
			"attempt_id", req.GetAttemptId(),
			"tenant_id", slug,
			"error", eerr.Error(),
		)
		return nil, status.Error(codes.Internal, "failed to complete signup")
	}

	// ---- consume the session ----
	// After this the completion cookie is inert, so a copy of it cannot be
	// replayed into a second tenant.
	if cerr := s.signupVerifications.MarkConsumed(ctx, req.GetVerifiedSessionToken()); cerr != nil {
		// The tenant is enqueued and the owner exists; failing now would tell
		// the caller to retry work that succeeded. Log loudly — an
		// un-consumed session is a replay window until it expires.
		s.logger.ErrorContext(ctx, "Signup: consuming verified session failed",
			"attempt_id", req.GetAttemptId(), "error", cerr.Error())
	}

	s.logger.InfoContext(ctx, "Signup: tenant enqueued for operator-pull provisioning",
		"attempt_id", req.GetAttemptId(),
		"tenant_id", slug,
	)

	return &tenantv1.SignupResponse{
		TenantId:    slug,
		OwnerUserId: result.UserID,
		// The resolved canonical plan id — the same value enqueued above, so the
		// id the caller bills on is the id the gate accepted and the operator
		// provisions, by construction rather than by the caller re-deriving it
		// (gibson#1325).
		PlanId: plan.ID,
	}, nil
}

// resolveSignupPlan is the server-side plan gate for self-serve signup. It
// answers "may this request provision a tenant at this tier?" and returns the
// canonical plan on success, or a ready-to-return gRPC status on refusal.
//
// Three rules, all fail-closed:
//
//  1. The tier MUST resolve to a canonical plan. An unknown, legacy, or
//     mis-cased id is InvalidArgument — never coerced to a default plan.
//
//  2. The plan MUST be self-serve. The contact-sales on-prem plan has no
//     Stripe product and no trial, so a self-serve signup can never
//     legitimately land on it; requesting it is PermissionDenied and the
//     caller is pointed at the administrator path (AdminProvisionTenant).
//
//  3. A paid plan MUST come with a billing customer WHEN the deployment
//     enforces entitlements (GIBSON_ENTITLEMENTS_REQUIRED=true — the SaaS
//     overlay, deploy#1055). The card-first signup flow creates the Stripe
//     customer and subscription BEFORE calling Signup and passes the customer
//     id here, so an empty id in SaaS mode means the caller skipped payment
//     setup entirely. Self-hosted installs leave the knob unset and are
//     unaffected: ADR-0006 makes the billing seam bypassable on-prem by
//     design, and this gate must not turn Stripe into an on-prem dependency.
//
// Rule 3 is a presence check, not a proof of payment — the daemon cannot talk
// to Stripe (that lives entirely behind the closed billing seam). The
// subsequent enforcement point is the pending-provisioning drain, which
// withholds a paid-tier tenant until billing_active is recorded; see
// ListPendingTenantProvisioning.
func (s *DaemonServer) resolveSignupPlan(tier, stripeCustomerID string) (plans.Plan, error) {
	plan, ok := plans.Lookup(tier)
	if !ok {
		return plans.Plan{}, status.Errorf(codes.InvalidArgument,
			"tier is not a known plan; valid self-serve plans are %s",
			strings.Join(plans.SelfServeIDs(), ", "))
	}
	if !plan.SelfServe {
		return plans.Plan{}, status.Errorf(codes.PermissionDenied,
			"plan %q is not available through self-serve signup; contact sales to have an administrator provision it",
			plan.ID)
	}
	if plan.Paid && entitlements.Required() && strings.TrimSpace(stripeCustomerID) == "" {
		return plans.Plan{}, status.Errorf(codes.PermissionDenied,
			"plan %q requires an active billing customer; complete payment setup before signing up",
			plan.ID)
	}
	return plan, nil
}
