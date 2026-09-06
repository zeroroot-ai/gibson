// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — billing_webhook_auth.go
//
// In-handler authentication for the billing-webhook write
// (TenantProvisioningService.SetTenantBillingActive).
//
// # Why a shared-secret HMAC and not a SPIFFE peer policy
//
// The daemon already has two mechanisms for "prove the caller is the component
// we think it is":
//
//  1. The SPIFFE direct-dial peer/method policy (operator_method_policy.go),
//     which matches the peer's X.509 SVID against a per-method allowlist. It
//     cannot gate this RPC. The caller is the dashboard, and the dashboard
//     never opens a direct daemon channel — its traffic transits Envoy +
//     ext-authz, so the SVID the daemon observes on this connection is
//     ENVOY's. Envoy's SVID is identical for every request it proxies, so a
//     peer policy here would authorise the route, which is precisely the
//     control that was already relied on and found insufficient: any caller
//     reaching that route could flip billing_active for any tenant.
//
//  2. The HMAC-signed header bundle in internal/infra/authz (ext-authz signs
//     the identity headers, the daemon recomputes and constant-time compares).
//     That mechanism survives an Envoy hop precisely because it binds the
//     ASSERTION, not the connection. This file applies the same shape to the
//     billing write: the dashboard's Stripe-webhook handler signs the two
//     request fields plus a timestamp with a secret only it and the daemon
//     hold, and the daemon recomputes.
//
// So: mechanism 2, because it is the only one of the two that can distinguish
// the dashboard's webhook handler from an arbitrary client on the same Envoy
// route, and because it is already the codebase's answer to that question.
//
// # Failure posture
//
// Fail-closed at every branch, including "not configured": with no secret the
// daemon cannot authenticate any caller, so it authenticates none. An
// unconfigured deployment therefore refuses the write rather than accepting
// every write. Self-hosted installs that never run a Stripe webhook simply
// never call this RPC.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Metadata keys carrying the billing-webhook assertion. gRPC metadata keys are
// lowercase on the wire; these constants are already in that form so a caller
// can use them verbatim.
const (
	// BillingWebhookSignatureKey carries the lowercase hex HMAC-SHA256 of the
	// canonical message (see billingWebhookMessage).
	BillingWebhookSignatureKey = "x-gibson-billing-signature"

	// BillingWebhookIssuedAtKey carries the signing time as decimal Unix
	// seconds. It is part of the signed message, so it cannot be adjusted
	// without invalidating the signature.
	BillingWebhookIssuedAtKey = "x-gibson-billing-issued-at"
)

// billingWebhookSkew bounds how far the signing timestamp may sit from the
// daemon's clock in either direction. It caps the replay window for a captured
// assertion and mirrors identityFreshnessSkewDefault in internal/infra/authz so
// the two signed-assertion surfaces agree on freshness.
const billingWebhookSkew = 60 * time.Second

// errBillingWebhookUnauth is the SINGLE refusal returned for every
// authentication failure — absent metadata, malformed timestamp, stale
// timestamp, wrong signature, unconfigured secret. Distinguishing them in the
// response would tell an attacker which half of the assertion to work on, and
// the "unconfigured" case would additionally advertise that the deployment has
// no secret set. The daemon log records which branch fired.
var errBillingWebhookUnauth = status.Error(codes.PermissionDenied,
	"billing webhook assertion missing or invalid")

// billingWebhookMessage builds the canonical signed message. Every field the
// handler acts on is covered, so a captured assertion cannot be replayed
// against a different tenant or flipped from active to inactive:
//
//	v1\n<tenant_id>\n<active>\n<issued_at>
//
// The version prefix lets the scheme rotate without ambiguity. active is
// rendered by strconv.FormatBool ("true"/"false"); issued_at is the decimal
// Unix seconds string exactly as it appears in metadata (not reformatted), so
// signer and verifier cannot disagree on its rendering.
func billingWebhookMessage(tenantID string, active bool, issuedAt string) []byte {
	var b strings.Builder
	b.WriteString("v1\n")
	b.WriteString(tenantID)
	b.WriteString("\n")
	b.WriteString(strconv.FormatBool(active))
	b.WriteString("\n")
	b.WriteString(issuedAt)
	return []byte(b.String())
}

// signBillingWebhook computes the lowercase-hex assertion for one request. It
// is the reference implementation of the wire format for any client, and the
// test helper for this package.
func signBillingWebhook(secret []byte, tenantID string, active bool, issuedAt string) string {
	m := hmac.New(sha256.New, secret)
	m.Write(billingWebhookMessage(tenantID, active, issuedAt))
	return hex.EncodeToString(m.Sum(nil))
}

// authorizeBillingWebhook authenticates a SetTenantBillingActive call against
// the configured shared secret. It returns nil only when the request carries a
// fresh signature computed over exactly this tenant_id and active value.
//
// now is injected so the freshness window is testable; production callers pass
// time.Now.
func (s *DaemonServer) authorizeBillingWebhook(ctx context.Context, tenantID string, active bool, now time.Time) error {
	if len(s.billingWebhookSecret) == 0 {
		s.logger.WarnContext(ctx, "billing webhook write refused: no webhook secret configured on this daemon",
			"tenant_id", tenantID)
		return errBillingWebhookUnauth
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.WarnContext(ctx, "billing webhook write refused: no request metadata", "tenant_id", tenantID)
		return errBillingWebhookUnauth
	}

	issuedAt := firstMD(md, BillingWebhookIssuedAtKey)
	sig := firstMD(md, BillingWebhookSignatureKey)
	if issuedAt == "" || sig == "" {
		s.logger.WarnContext(ctx, "billing webhook write refused: assertion headers absent", "tenant_id", tenantID)
		return errBillingWebhookUnauth
	}

	secs, err := strconv.ParseInt(issuedAt, 10, 64)
	if err != nil {
		s.logger.WarnContext(ctx, "billing webhook write refused: malformed issued-at", "tenant_id", tenantID)
		return errBillingWebhookUnauth
	}
	if delta := now.Sub(time.Unix(secs, 0)); delta > billingWebhookSkew || delta < -billingWebhookSkew {
		s.logger.WarnContext(ctx, "billing webhook write refused: assertion outside freshness window",
			"tenant_id", tenantID, "skew_seconds", int64(delta.Seconds()))
		return errBillingWebhookUnauth
	}

	want := signBillingWebhook(s.billingWebhookSecret, tenantID, active, issuedAt)
	// Constant-time over the hex strings: subtle.ConstantTimeCompare is
	// length-safe (it returns 0 for unequal lengths) and both operands here are
	// fixed-width hex, so no length is leaked either way.
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		s.logger.WarnContext(ctx, "billing webhook write refused: signature mismatch", "tenant_id", tenantID)
		return errBillingWebhookUnauth
	}
	return nil
}

// firstMD returns the first value for key, or "" when absent. gRPC lowercases
// metadata keys on receipt, so the lookup is done on the lowercased key.
func firstMD(md metadata.MD, key string) string {
	v := md.Get(strings.ToLower(key))
	if len(v) == 0 {
		return ""
	}
	return strings.TrimSpace(v[0])
}
