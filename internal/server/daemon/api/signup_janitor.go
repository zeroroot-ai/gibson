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
	expired, deleted, err := s.signupVerifications.PurgeExpired(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "signup janitor: sweep failed", "error", err.Error())
		return
	}
	if expired > 0 || deleted > 0 {
		s.logger.InfoContext(ctx, "signup janitor: swept signup_verification",
			"expired", expired, "deleted", deleted)
	}
	s.expireStalePendingRegistrations(ctx)
}

// signupJanitorDecider names the janitor in the audit record of a registration
// it rejects.
const signupJanitorDecider = "system:signup-janitor"

// expireStalePendingRegistrations rejects each registration that waited past
// SignupRegistrationTTL and frees its workspace name (gibson#1191).
//
// It takes the same steps as AdminRejectRegistration: claim the decision, write
// the audit record, remove the workspace org. The claim has the one-decision
// predicate, so an administrator who decides the row at the same moment wins or
// loses cleanly and the row is never decided twice.
func (s *DaemonServer) expireStalePendingRegistrations(ctx context.Context) {
	if s.idpAdminClient == nil {
		return
	}
	rows, err := s.signupVerifications.ListExpiredPendingApprovals(ctx, SignupApprovalPageSize)
	if err != nil {
		s.logger.ErrorContext(ctx, "signup janitor: listing expired registrations failed", "error", err.Error())
		return
	}
	for _, r := range rows {
		row, err := s.signupVerifications.RejectRegistration(ctx, r.ID, signupJanitorDecider)
		if err != nil {
			// Not found means an administrator decided it first.
			if !errors.Is(err, ErrSignupVerificationNotFound) {
				s.logger.ErrorContext(ctx, "signup janitor: rejecting an expired registration failed",
					"registration_id", r.ID, "error", err.Error())
			}
			continue
		}
		if err := s.recordRegistrationDecision(ctx, signupJanitorDecider, row,
			"signup_registration.expired", "no decision before the registration expired", uuid.NewString()); err != nil {
			s.logger.ErrorContext(ctx, "signup janitor: the audit record of an expiry could not be written",
				"registration_id", row.ID, "error", err.Error())
		}
		s.dropRejectedWorkspace(ctx, row)
		s.logger.InfoContext(ctx, "signup janitor: expired registration rejected, workspace name freed",
			"registration_id", row.ID)
	}
}
