// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — signup_wiring.go
//
// Construction seams and link builders for the signup verification flow.
// Separated from signup_service.go so the handlers read as policy and this
// file reads as configuration.
package api

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
)

// signupVerificationSender is the narrow mail surface the handlers use. An
// interface rather than the concrete sender so tests can assert which of the
// two messages was sent without an SMTP server.
type signupVerificationSender interface {
	SendSignupVerification(ctx context.Context, v mailer.VerificationEmail) error
	SendAccountExists(ctx context.Context, a mailer.AccountExistsEmail) error
}

// signupLimiter is the narrow limiter surface the signup handlers use.
//
// Peek is part of it because the handlers hold several budgets per request and
// must be able to decide the request without charging any of them. See
// checkSignupLimits.
type signupLimiter interface {
	Peek(ctx context.Context, key string, w ratelimit.Window) error
	Check(ctx context.Context, key string, w ratelimit.Window) error
}

// signupVerificationStore is the store surface the handlers program against.
//
// An interface rather than the concrete type so handler tests can substitute an
// in-memory implementation and exercise the ordering rules without a database.
// *SignupVerificationStore is the only production implementation; its SQL
// carries the single-use and expiry predicates and is pinned by its own tests.
type signupVerificationStore interface {
	Issue(ctx context.Context, p IssueParams) (SignupVerification, string, error)
	MarkSent(ctx context.Context, id string) error
	MarkSendFailed(ctx context.Context, id string) error
	MarkConsumedByID(ctx context.Context, id string) error
	LastSentAt(ctx context.Context, email string) (time.Time, bool, error)
	RedeemToken(ctx context.Context, rawToken string) (SignupVerification, string, error)
	GetByVerifiedSession(ctx context.Context, rawSession string) (SignupVerification, error)
	AttachStripeCustomer(ctx context.Context, rawSession, customerID string) error
	ClaimCompletion(ctx context.Context, rawSession string) (SignupVerification, error)
	MarkConsumed(ctx context.Context, rawSession string) error
	PurgeExpired(ctx context.Context) (expired, deleted int64, err error)
}

var _ signupVerificationStore = (*SignupVerificationStore)(nil)

// WithSignupVerificationStore wires the platform-Postgres store that holds
// proof of mailbox control.
//
// Required for self-serve signup. When absent the handlers return Unavailable
// rather than proceeding: without somewhere to record that an address was
// proven, the only way to continue would be to skip the proof.
func (s *DaemonServer) WithSignupVerificationStore(store signupVerificationStore) *DaemonServer {
	s.signupVerifications = store
	return s
}

// WithSignupMailer wires the sender for the two signup messages.
//
// Required for self-serve signup, for the same reason: no transport means no
// proof is obtainable.
func (s *DaemonServer) WithSignupMailer(m signupVerificationSender) *DaemonServer {
	s.signupMailer = m
	return s
}

// EnvAppURL names the product-surface origin — the host that serves the signup
// pages, i.e. app.<domain>.
//
// It is deliberately NOT GIBSON_PUBLIC_URL. That variable carries the API-plane
// origin (api.<domain>): it is what the daemon stamps into capability-grant
// discovery and the enroll command, and the API vhost serves no product routes
// at all. Building a user-facing link from it produced a link to a host where
// the path does not exist, so nobody could finish signing up — and it sent the
// link, token and all, through an edge that access-logs request paths.
const EnvAppURL = "GIBSON_APP_URL"

// WithAppURL wires the product-surface origin used to build user-facing links.
func (s *DaemonServer) WithAppURL(u string) *DaemonServer {
	s.appURL = strings.TrimRight(strings.TrimSpace(u), "/")
	return s
}

// WithSignupLimiter wires the sliding-window limiter guarding the
// unauthenticated signup RPCs. When absent the handlers refuse — see
// signup_rate_limit.go for why that is fail-closed rather than degraded.
func (s *DaemonServer) WithSignupLimiter(l signupLimiter) *DaemonServer {
	s.signupLimiter = l
	return s
}

// signupNow is the handlers' clock, injectable for tests.
func (s *DaemonServer) signupNow() time.Time {
	if s.signupClock != nil {
		return s.signupClock()
	}
	return time.Now().UTC()
}

// SignupVerifyPath is the product-surface route the emailed link targets. It
// must name a route the dashboard actually serves — app/(public)/signup/verify.
// Changing it here without changing it there breaks every signup.
const SignupVerifyPath = "/signup/verify"

// signupBaseURL is the product-surface origin links in signup email point at.
func (s *DaemonServer) signupBaseURL() string {
	return strings.TrimRight(s.appURL, "/")
}

// signupContinueURL builds the emailed verification link.
//
// The raw token exists here, in the message body, and in the request the
// recipient makes when they open the link. It is never logged by the daemon,
// never returned in an RPC response, and never stored — the database holds only
// its hash.
//
// KNOWN RESIDUAL: because it rides in the query string, an edge that
// access-logs request paths records it on the one request that redeems it. That
// is bounded rather than eliminated: the token is single-use and short-lived,
// so a copy recovered from a log is spent by the time it is read. Moving it out
// of the URL entirely is the real fix and is not this change.
func (s *DaemonServer) signupContinueURL(rawToken string) string {
	base := s.signupBaseURL()
	if base == "" {
		// Still emit a usable relative link rather than an empty one; a
		// misconfigured origin should be visible as a broken link, not as a
		// silently tokenless email. Startup refuses this configuration on the
		// self-serve profile, so it is only reachable in tests.
		return SignupVerifyPath + "?token=" + url.QueryEscape(rawToken)
	}
	return base + SignupVerifyPath + "?token=" + url.QueryEscape(rawToken)
}

// signupSignInURL / signupPasswordResetURL are the two links in the
// account-exists notice. Neither carries a token: the notice is informational,
// and any credential change goes through the IdP's own flow, which proves
// mailbox control itself.
func (s *DaemonServer) signupSignInURL() string {
	base := s.signupBaseURL()
	if base == "" {
		return ""
	}
	return base + "/login"
}

func (s *DaemonServer) signupPasswordResetURL() string {
	base := s.signupBaseURL()
	if base == "" {
		return ""
	}
	return base + "/login?prompt=reset"
}
