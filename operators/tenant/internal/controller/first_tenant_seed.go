// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// defaultFirstTenantSeedInterval is how often the seed retries the enqueue
// until the daemon accepts it once.
const defaultFirstTenantSeedInterval = 10 * time.Second

// TenantProvisioningEnqueuer is the slice of the daemon client the first-tenant
// seed needs. provision.EntitlementsGRPCClient satisfies it; tests pass a stub.
type TenantProvisioningEnqueuer interface {
	EnqueueTenantProvisioning(ctx context.Context, t provision.PendingTenant) (alreadyExisted bool, err error)
}

// FirstTenantSeedRunnable enqueues the first tenant on a fresh self-hosted
// install (gibson#1496). It is the session-less half of first-admin bring-up:
// the interactive AdminProvisionTenant RPC is gated by a session-revocation
// check no headless caller can satisfy, so the operator — which already holds a
// SPIFFE identity trusted by the daemon's operator surface — enqueues the first
// tenant here over EnqueueTenantProvisioning. The existing
// PendingProvisioningRunnable then drains the row exactly as it would a
// signup-originated one (Tenant CR + Zitadel org), and bootstrap-tenant-owner
// creates the owner user afterwards.
//
// It runs once: the enqueue is idempotent on tenant_id (daemon ON CONFLICT), so
// a re-run after a restart is a no-op and logged as "already seeded". The seed
// retries only until the daemon accepts the row once — a daemon still starting
// up must not make the seed give up — then returns. It never crashes the
// manager; a persistent failure is logged every tick and visible in the
// operator log.
type FirstTenantSeedRunnable struct {
	Daemon      TenantProvisioningEnqueuer
	TenantID    string
	DisplayName string
	OwnerEmail  string
	Tier        string
	// Interval between retries until the first successful enqueue. Zero uses
	// defaultFirstTenantSeedInterval.
	Interval time.Duration
}

// NeedLeaderElection ensures only the lead replica seeds, so two replicas never
// both enqueue (the daemon's ON CONFLICT would make the loser a no-op anyway,
// but single-writer is cleaner and matches PendingProvisioningRunnable).
func (r *FirstTenantSeedRunnable) NeedLeaderElection() bool { return true }

// SetupWithManager registers the seed as a manager.Runnable.
func (r *FirstTenantSeedRunnable) SetupWithManager(mgr manager.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("add first-tenant seed runnable to manager: %w", err)
	}
	return nil
}

// FirstTenantSeedFromEnv builds the seed from the operator's FIRST_TENANT_*
// environment, injected as getenv for testability (mirrors
// selectStripeCustomerVerifier, same package). It returns enabled=false when
// FIRST_TENANT_ENABLED is not "true" so main.go can skip registration, and an
// error when the seed is switched on but its required identity is missing —
// which main.go turns into a fail-fast exit, so a misconfigured chart is caught
// at boot rather than silently never seeding.
func FirstTenantSeedFromEnv(getenv func(string) string, daemon TenantProvisioningEnqueuer) (seed *FirstTenantSeedRunnable, enabled bool, err error) {
	if getenv("FIRST_TENANT_ENABLED") != "true" {
		return nil, false, nil
	}
	tenantID := getenv("FIRST_TENANT_ID")
	ownerEmail := getenv("FIRST_TENANT_OWNER_EMAIL")
	if tenantID == "" || ownerEmail == "" {
		return nil, true, errors.New("FIRST_TENANT_ENABLED=true but FIRST_TENANT_ID or FIRST_TENANT_OWNER_EMAIL is empty")
	}
	return &FirstTenantSeedRunnable{
		Daemon:      daemon,
		TenantID:    tenantID,
		DisplayName: getenv("FIRST_TENANT_DISPLAY_NAME"),
		OwnerEmail:  ownerEmail,
		Tier:        getenv("FIRST_TENANT_TIER"),
	}, true, nil
}

// RegisterFirstTenantSeed wires the first-tenant seed into the manager from the
// FIRST_TENANT_* environment, if enabled. It is the single entry point main.go
// calls, so the enable/parse/register/log sequence is covered by tests rather
// than living uncovered in package main. Returns an error the caller turns into
// a fail-fast exit: a seed switched on but misconfigured, or a manager that
// refuses the runnable, must stop boot rather than silently never seed.
func RegisterFirstTenantSeed(mgr manager.Manager, getenv func(string) string, daemon TenantProvisioningEnqueuer, logger logr.Logger) error {
	seed, enabled, err := FirstTenantSeedFromEnv(getenv, daemon)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if err := seed.SetupWithManager(mgr); err != nil {
		return err
	}
	logger.Info("first-tenant seed enabled", "tenant_id", seed.TenantID, "owner_email", seed.OwnerEmail)
	return nil
}

// Start enqueues the first tenant, retrying until the daemon accepts it once,
// then returns. Returns nil on context cancellation.
func (r *FirstTenantSeedRunnable) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("first-tenant-seed")
	if r.TenantID == "" || r.OwnerEmail == "" {
		// Registered without the required fields — refuse rather than enqueue a
		// malformed row. main.go only registers the seed when both are set, so
		// this is a belt-and-braces guard.
		return errors.New("first-tenant seed misconfigured: tenant_id and owner_email are required")
	}
	interval := r.Interval
	if interval <= 0 {
		interval = defaultFirstTenantSeedInterval
	}

	if r.seedOnce(ctx, logger) {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if r.seedOnce(ctx, logger) {
				return nil
			}
		}
	}
}

// seedOnce attempts the enqueue once. Returns true when the seed is done (the
// daemon accepted the row, whether freshly inserted or already present), false
// to retry on the next tick.
func (r *FirstTenantSeedRunnable) seedOnce(ctx context.Context, logger logr.Logger) bool {
	alreadyExisted, err := r.Daemon.EnqueueTenantProvisioning(ctx, provision.PendingTenant{
		TenantID:      r.TenantID,
		WorkspaceName: r.DisplayName,
		OwnerEmail:    r.OwnerEmail,
		Tier:          r.Tier,
	})
	if err != nil {
		logger.Error(err, "first-tenant seed enqueue failed; will retry",
			"tenant_id", r.TenantID)
		return false
	}
	if alreadyExisted {
		logger.Info("first tenant already seeded; nothing to do", "tenant_id", r.TenantID)
	} else {
		logger.Info("first tenant enqueued for provisioning",
			"tenant_id", r.TenantID, "owner_email", r.OwnerEmail, "tier", r.Tier)
	}
	return true
}

var _ manager.Runnable = (*FirstTenantSeedRunnable)(nil)
