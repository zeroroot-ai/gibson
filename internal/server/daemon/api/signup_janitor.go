// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — signup_janitor.go
//
// Hourly sweep of abandoned signup verifications.
//
// This is the whole cleanup story for signups that were never completed, and it
// is short because of the ordering the flow now enforces: an abandoned attempt
// leaves one row and some Redis counters, and the counters expire on their own
// TTL. There is no orphaned identity to reap, no orphaned tenant, and no
// billing object created before the address was proven.
package api

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/platform/signup"
)

// signupJanitorInterval is how often the sweep runs. Rows self-describe their
// expiry, so the cadence only affects how promptly a dead row stops occupying
// the resend-cooldown index.
const signupJanitorInterval = time.Hour

// RunSignupJanitor sweeps signup_verification until ctx is cancelled.
//
// It ages unredeemed rows past their expiry to 'expired' and deletes terminal
// rows past the retention window. Errors are logged and the loop continues: a
// janitor that stops on the first transient database error is a janitor that
// silently stops running.
//
// The verification store is required. The daemon starts the janitor only
// after it wires the store.
func (s *DaemonServer) RunSignupJanitor(ctx context.Context) {
	ticker := time.NewTicker(signupJanitorInterval)
	defer ticker.Stop()

	// Sweep once at startup so a daemon that was down over a long window does
	// not wait a full interval before clearing it.
	s.sweepSignupVerifications(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepSignupVerifications(ctx)
		}
	}
}

func (s *DaemonServer) sweepSignupVerifications(ctx context.Context) {
	// The two steps are independent: a failed purge must not stop the expiry
	// of a registration that holds a workspace name.
	expired, deleted, err := s.signupVerifications.PurgeExpired(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "signup janitor: sweep failed", "error", err.Error())
	} else if expired > 0 || deleted > 0 {
		s.logger.InfoContext(ctx, "signup janitor: swept signup_verification",
			"expired", expired, "deleted", deleted)
	}
	// Only the approval rung has registrations that wait for a decision. The
	// daemon refuses to start on that rung without the identity provider
	// client (grpc.go), so the client is present here.
	if s.signupPolicy == signup.PolicyApproval {
		s.expireStalePendingRegistrations(ctx)
	}
}

// signupJanitorDecider names the janitor in the audit record of a registration
// it expires.
const signupJanitorDecider = "system:signup-janitor"

// expireStalePendingRegistrations frees the workspace name of each
// registration that waited past SignupRegistrationTTL (gibson#1191).
//
// The order never deletes the org before the claim. The claim moves the row to
// 'expiring' with the one-decision predicate, so an administrator who decides
// the row at the same moment wins or loses cleanly. The org is then removed,
// and only after that the row becomes 'rejected'. A failed removal leaves the
// row 'expiring', and the next sweep retries it.
func (s *DaemonServer) expireStalePendingRegistrations(ctx context.Context) {
	rows, err := s.signupVerifications.ListExpiringRegistrations(ctx, SignupApprovalPageSize)
	if err != nil {
		s.logger.ErrorContext(ctx, "signup janitor: listing expiring registrations failed", "error", err.Error())
		return
	}
	for _, r := range rows {
		row := r
		if r.Status != signupStatusExpiring {
			claimed, err := s.signupVerifications.BeginExpiry(ctx, r.ID, signupJanitorDecider)
			if err != nil {
				// Not found means an administrator decided it first.
				if !errors.Is(err, ErrSignupVerificationNotFound) {
					s.logger.ErrorContext(ctx, "signup janitor: claiming an expired registration failed",
						"registration_id", r.ID, "error", err.Error())
				}
				continue
			}
			row = claimed
			if err := s.recordRegistrationDecision(ctx, signupJanitorDecider, row,
				"signup_registration.expired", "no decision before the registration expired", uuid.NewString()); err != nil {
				s.logger.ErrorContext(ctx, "signup janitor: the audit record of an expiry could not be written",
					"registration_id", row.ID, "error", err.Error())
			}
		}
		if err := s.releaseWorkspaceOrg(ctx, row); err != nil {
			s.logger.ErrorContext(ctx, "signup janitor: could not remove the workspace org; it retries on the next sweep",
				"registration_id", row.ID, "error", err.Error())
			continue
		}
		if err := s.signupVerifications.CompleteExpiry(ctx, row.ID); err != nil {
			s.logger.ErrorContext(ctx, "signup janitor: could not finish an expiry; it retries on the next sweep",
				"registration_id", row.ID, "error", err.Error())
			continue
		}
		s.logger.InfoContext(ctx, "signup janitor: expired registration rejected, workspace name freed",
			"registration_id", row.ID)
	}
}
