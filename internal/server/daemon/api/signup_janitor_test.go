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

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
)

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

// TestSweep_ExpiredPendingRegistrationFreesItsWorkspaceName proves gibson#1191:
// a registration nobody decided gives its workspace name back after its TTL.
func TestSweep_ExpiredPendingRegistrationFreesItsWorkspaceName(t *testing.T) {
	h, auditWriter := newApprovalHarness(t)
	regID := registerPending(t, h)

	// Still inside the TTL: nothing happens.
	h.advance(SignupRegistrationTTL - time.Hour)
	h.srv.sweepSignupVerifications(context.Background())
	if got := h.store.rows[regID].status; got != signupStatusPendingApproval {
		t.Fatalf("status inside the TTL = %q, want it still pending", got)
	}
	if len(h.idp.deletedOrgs) != 0 {
		t.Fatalf("orgs deleted inside the TTL: %v", h.idp.deletedOrgs)
	}

	// Past the TTL: the registration is rejected and the org is removed.
	h.advance(2 * time.Hour)
	h.srv.sweepSignupVerifications(context.Background())
	if got := h.store.rows[regID].status; got != signupStatusRejected {
		t.Fatalf("status after the TTL = %q, want %q", got, signupStatusRejected)
	}
	if len(h.idp.deletedOrgs) != 1 || h.idp.deletedOrgs[0] != "org-1" {
		t.Fatalf("deleted orgs = %v, want the workspace org freed", h.idp.deletedOrgs)
	}
	var audited bool
	for _, ev := range auditWriter.events {
		if ev.Action == "signup_registration.expired" && ev.ActorID == signupJanitorDecider {
			audited = true
		}
	}
	if !audited {
		t.Error("an expiry must leave an audit record naming the janitor")
	}
}

// TestSweep_FailedOrgRemovalIsRetried proves the name is never held forever:
// a removal that fails once leaves the row 'expiring', and the next sweep
// finishes it (gibson#1191).
func TestSweep_FailedOrgRemovalIsRetried(t *testing.T) {
	h, auditWriter := newApprovalHarness(t)
	regID := registerPending(t, h)
	h.advance(SignupRegistrationTTL + time.Hour)

	h.idp.deleteOrgErr = errors.New("zitadel down")
	h.srv.sweepSignupVerifications(context.Background())
	if got := h.store.rows[regID].status; got != signupStatusExpiring {
		t.Fatalf("status after a failed removal = %q, want %q", got, signupStatusExpiring)
	}

	h.idp.deleteOrgErr = nil
	h.srv.sweepSignupVerifications(context.Background())
	if got := h.store.rows[regID].status; got != signupStatusRejected {
		t.Fatalf("status after the retry = %q, want %q", got, signupStatusRejected)
	}
	if len(h.idp.deletedOrgs) != 2 {
		t.Fatalf("deleted orgs = %v, want the removal tried twice", h.idp.deletedOrgs)
	}
	var records int
	for _, ev := range auditWriter.events {
		if ev.Action == "signup_registration.expired" {
			records++
		}
	}
	if records != 1 {
		t.Errorf("expiry audit records = %d, want 1 (a retry writes none)", records)
	}
}

// An org that is already gone counts as removed.
func TestSweep_OrgAlreadyGoneCountsAsRemoved(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	h.advance(SignupRegistrationTTL + time.Hour)

	h.idp.deleteOrgErr = idp.ErrNotFound
	h.srv.sweepSignupVerifications(context.Background())
	if got := h.store.rows[regID].status; got != signupStatusRejected {
		t.Fatalf("status = %q, want %q", got, signupStatusRejected)
	}
}

// A failed purge must not stop the expiry step.
func TestSweep_PurgeFailureDoesNotSkipExpiry(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	h.advance(SignupRegistrationTTL + time.Hour)

	h.store.purgeErr = errors.New("connection reset")
	h.srv.sweepSignupVerifications(context.Background())
	if got := h.store.rows[regID].status; got != signupStatusRejected {
		t.Fatalf("status = %q, want %q even though the purge failed", got, signupStatusRejected)
	}
}

// Each failure of the expiry steps is logged and the sweep goes on. Nothing
// panics, and the row stays where the failure left it.
func TestSweep_ExpiryFailuresAreLoggedAndSurvived(t *testing.T) {
	t.Run("listing fails", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		registerPending(t, h)
		h.advance(SignupRegistrationTTL + time.Hour)
		h.store.listExpiringErr = errors.New("read failed")
		h.srv.sweepSignupVerifications(context.Background())
		if len(h.idp.deletedOrgs) != 0 {
			t.Fatalf("deleted orgs = %v, want none when the list failed", h.idp.deletedOrgs)
		}
	})

	t.Run("claim fails", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		regID := registerPending(t, h)
		h.advance(SignupRegistrationTTL + time.Hour)
		h.store.beginExpiryErr = errors.New("write failed")
		h.srv.sweepSignupVerifications(context.Background())
		if got := h.store.rows[regID].status; got != signupStatusPendingApproval {
			t.Fatalf("status = %q, want it unclaimed", got)
		}
		if len(h.idp.deletedOrgs) != 0 {
			t.Fatalf("an org was deleted before the claim: %v", h.idp.deletedOrgs)
		}
	})

	t.Run("audit write fails", func(t *testing.T) {
		h, auditWriter := newApprovalHarness(t)
		regID := registerPending(t, h)
		h.advance(SignupRegistrationTTL + time.Hour)
		auditWriter.syncErr = errors.New("audit down")
		h.srv.sweepSignupVerifications(context.Background())
		if got := h.store.rows[regID].status; got != signupStatusRejected {
			t.Fatalf("status = %q, want the expiry to finish despite the audit failure", got)
		}
	})

	t.Run("completion fails", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		regID := registerPending(t, h)
		h.advance(SignupRegistrationTTL + time.Hour)
		h.store.completeExpiryErr = errors.New("write failed")
		h.srv.sweepSignupVerifications(context.Background())
		if got := h.store.rows[regID].status; got != signupStatusExpiring {
			t.Fatalf("status = %q, want expiring so the next sweep retries", got)
		}
		h.store.completeExpiryErr = nil
		h.srv.sweepSignupVerifications(context.Background())
		if got := h.store.rows[regID].status; got != signupStatusRejected {
			t.Fatalf("status after the retry = %q, want rejected", got)
		}
	})
}

// An administrator who claims the registration first wins. A later sweep past
// the TTL neither deletes the org nor changes the row (gibson#1191).
func TestSweep_AdminApprovalWinsTheRace(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	if _, err := h.store.ClaimApproval(context.Background(), regID, "admin-1"); err != nil {
		t.Fatalf("ClaimApproval: %v", err)
	}
	h.advance(SignupRegistrationTTL + time.Hour)

	h.srv.sweepSignupVerifications(context.Background())

	if got := h.store.rows[regID].status; got != signupStatusConsumed {
		t.Fatalf("status = %q, want %q", got, signupStatusConsumed)
	}
	if len(h.idp.deletedOrgs) != 0 {
		t.Fatalf("the janitor deleted orgs %v after an administrator approved", h.idp.deletedOrgs)
	}
}

// The janitor loses the claim to an administrator who decides between its
// listing and its claim: the claim finds nothing and no org goes.
func TestSweep_LosingTheClaimDeletesNothing(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	h.advance(SignupRegistrationTTL + time.Hour)
	h.store.beginExpiryErr = ErrSignupVerificationNotFound

	h.srv.sweepSignupVerifications(context.Background())

	if got := h.store.rows[regID].status; got != signupStatusPendingApproval {
		t.Fatalf("status = %q, want it left to the administrator", got)
	}
	if len(h.idp.deletedOrgs) != 0 {
		t.Fatalf("deleted orgs = %v, want none", h.idp.deletedOrgs)
	}
}

// releaseWorkspaceOrg reports an identity provider failure to its caller.
func TestReleaseWorkspaceOrg_Failures(t *testing.T) {
	h, _ := newApprovalHarness(t)
	row := SignupVerification{ID: "r1", OwnerUserID: "user-1"}

	h.idp.orgOfUserErr = errors.New("zitadel down")
	if err := h.srv.releaseWorkspaceOrg(context.Background(), row); err == nil {
		t.Error("a failed org lookup must be reported")
	}

	h.idp.orgOfUserErr = nil
	h.idp.orgByUser = map[string]string{"user-1": "org-1"}
	h.idp.deleteOrgErr = errors.New("zitadel down")
	if err := h.srv.releaseWorkspaceOrg(context.Background(), row); err == nil {
		t.Error("a failed org delete must be reported")
	}

	if err := h.srv.releaseWorkspaceOrg(context.Background(), SignupVerification{}); err != nil {
		t.Errorf("a registration with no owner has no org to remove: %v", err)
	}
}
