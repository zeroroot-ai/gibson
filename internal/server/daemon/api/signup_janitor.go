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
	"time"
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
// Safe to call when no store is wired — it returns immediately rather than
// spinning.
func (s *DaemonServer) RunSignupJanitor(ctx context.Context) {
	if s.signupVerifications == nil {
		return
	}
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
}
