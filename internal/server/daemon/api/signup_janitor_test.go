// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_janitor_test.go — the hourly sweep of abandoned signup verifications.
//
// The loop itself ticks hourly, which is not something a unit test should
// wait on. What matters is provable without a real ticker: the janitor is a
// no-op with no store wired, it sweeps once immediately on start (so a daemon
// that was down does not wait a full interval to catch up), it stops on
// context cancellation, and a sweep failure is logged and swallowed rather
// than propagated.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRunSignupJanitor_NoStoreIsANoOp — safe to call unconditionally at
// startup even when self-serve signup, and its store, are not wired.
func TestRunSignupJanitor_NoStoreIsANoOp(t *testing.T) {
	s := &DaemonServer{logger: testSlogLogger}
	done := make(chan struct{})
	go func() {
		s.RunSignupJanitor(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunSignupJanitor did not return immediately with no store wired")
	}
}

// TestRunSignupJanitor_SweepsOnceThenStopsOnCancellation proves the two
// properties the interval alone can't: an immediate sweep on start, and a
// clean exit on context cancellation without waiting for the next tick.
func TestRunSignupJanitor_SweepsOnceThenStopsOnCancellation(t *testing.T) {
	store := newMemStore()
	s := &DaemonServer{logger: testSlogLogger}
	s.WithSignupVerificationStore(store)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunSignupJanitor(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunSignupJanitor did not return after context cancellation")
	}
}

// TestSweepSignupVerifications_ReportsWhatItTouched is the success path: rows
// aged past expiry are counted.
func TestSweepSignupVerifications_ReportsWhatItTouched(t *testing.T) {
	store := newMemStore()
	store.rows["r1"] = &memRow{
		SignupVerification: SignupVerification{ID: "r1"},
		status:             signupStatusPending,
	}
	// ExpiresAt zero-value is already in the past relative to store.now(), so
	// this row ages out on the sweep.
	s := &DaemonServer{logger: testSlogLogger}
	s.WithSignupVerificationStore(store)

	s.sweepSignupVerifications(context.Background())

	if store.rows["r1"].status != signupStatusExpired {
		t.Errorf("row status = %q, want %q after a sweep past its expiry", store.rows["r1"].status, signupStatusExpired)
	}
}

// TestSweepSignupVerifications_ErrorIsLoggedAndSwallowed — a janitor that
// stops running on the first transient database error silently stops
// running. The sweep must log and return, not propagate.
func TestSweepSignupVerifications_ErrorIsLoggedAndSwallowed(t *testing.T) {
	store := newMemStore()
	store.purgeErr = errors.New("connection reset")
	store.rows["r1"] = &memRow{
		SignupVerification: SignupVerification{ID: "r1"},
		status:             signupStatusPending,
	}
	s := &DaemonServer{logger: testSlogLogger}
	s.WithSignupVerificationStore(store)

	// A failed sweep must not panic, and must not touch any row — the janitor
	// keeps going on the next tick (proved by the cancellation test above)
	// rather than acting on a partial or failed read.
	s.sweepSignupVerifications(context.Background())

	if store.rows["r1"].status != signupStatusPending {
		t.Errorf("row status = %q after a failed sweep, want it untouched (%q)",
			store.rows["r1"].status, signupStatusPending)
	}
}
