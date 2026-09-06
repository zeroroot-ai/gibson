// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// stubEnqueuer records calls and returns scripted results. A non-nil errs[i]
// fails the i-th call; alreadyExisted is returned on the first success.
type stubEnqueuer struct {
	mu             sync.Mutex
	calls          []provision.PendingTenant
	failFirstN     int
	alreadyExisted bool
}

func (s *stubEnqueuer) EnqueueTenantProvisioning(_ context.Context, t provision.PendingTenant) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, t)
	if len(s.calls) <= s.failFirstN {
		return false, errors.New("daemon unreachable")
	}
	return s.alreadyExisted, nil
}

func (s *stubEnqueuer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func TestFirstTenantSeed_EnqueuesOnceThenReturns(t *testing.T) {
	enq := &stubEnqueuer{}
	r := &FirstTenantSeedRunnable{
		Daemon:      enq,
		TenantID:    "founding",
		DisplayName: "Founding Org",
		OwnerEmail:  "admin@selfhosted.example.com",
		Tier:        "enterprise",
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := enq.callCount(); got != 1 {
		t.Fatalf("want exactly 1 enqueue, got %d", got)
	}
	c := enq.calls[0]
	if c.TenantID != "founding" || c.OwnerEmail != "admin@selfhosted.example.com" ||
		c.WorkspaceName != "Founding Org" || c.Tier != "enterprise" {
		t.Errorf("unexpected pending tenant: %+v", c)
	}
}

func TestFirstTenantSeed_RetriesUntilAccepted(t *testing.T) {
	enq := &stubEnqueuer{failFirstN: 2}
	r := &FirstTenantSeedRunnable{
		Daemon:     enq,
		TenantID:   "founding",
		OwnerEmail: "admin@selfhosted.example.com",
		Interval:   5 * time.Millisecond,
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := enq.callCount(); got != 3 {
		t.Fatalf("want 3 enqueue attempts (2 failed + 1 ok), got %d", got)
	}
}

func TestFirstTenantSeed_AlreadyExisted_ReturnsNoRetry(t *testing.T) {
	enq := &stubEnqueuer{alreadyExisted: true}
	r := &FirstTenantSeedRunnable{
		Daemon:     enq,
		TenantID:   "founding",
		OwnerEmail: "admin@selfhosted.example.com",
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := enq.callCount(); got != 1 {
		t.Fatalf("want 1 enqueue on already-existed, got %d", got)
	}
}

func TestFirstTenantSeed_MisconfiguredMissingOwner_Errors(t *testing.T) {
	enq := &stubEnqueuer{}
	r := &FirstTenantSeedRunnable{Daemon: enq, TenantID: "founding"}
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("want error when owner_email is empty")
	}
	if got := enq.callCount(); got != 0 {
		t.Errorf("want 0 enqueue on misconfig, got %d", got)
	}
}

func TestFirstTenantSeed_ContextCancelledDuringRetry(t *testing.T) {
	enq := &stubEnqueuer{failFirstN: 1000} // never succeeds
	r := &FirstTenantSeedRunnable{
		Daemon:     enq,
		TenantID:   "founding",
		OwnerEmail: "admin@selfhosted.example.com",
		Interval:   5 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start should return nil on ctx cancel, got %v", err)
	}
	if enq.callCount() == 0 {
		t.Error("expected at least one attempt before cancellation")
	}
}

func TestFirstTenantSeedFromEnv(t *testing.T) {
	enq := &stubEnqueuer{}
	base := map[string]string{
		"FIRST_TENANT_ENABLED":      "true",
		"FIRST_TENANT_ID":           "default",
		"FIRST_TENANT_OWNER_EMAIL":  "admin@selfhosted.example.com",
		"FIRST_TENANT_DISPLAY_NAME": "Default Workspace",
		"FIRST_TENANT_TIER":         "enterprise",
	}
	getenvFrom := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	t.Run("disabled when flag not true", func(t *testing.T) {
		seed, enabled, err := FirstTenantSeedFromEnv(func(string) string { return "" }, enq)
		if err != nil || enabled || seed != nil {
			t.Fatalf("want (nil,false,nil), got (%v,%v,%v)", seed, enabled, err)
		}
	})

	t.Run("enabled + fully configured", func(t *testing.T) {
		seed, enabled, err := FirstTenantSeedFromEnv(getenvFrom(base), enq)
		if err != nil || !enabled || seed == nil {
			t.Fatalf("want a seed enabled with no error, got (%v,%v,%v)", seed, enabled, err)
		}
		if seed.TenantID != "default" || seed.OwnerEmail != "admin@selfhosted.example.com" ||
			seed.DisplayName != "Default Workspace" || seed.Tier != "enterprise" || seed.Daemon != enq {
			t.Errorf("seed fields not mapped from env: %+v", seed)
		}
	})

	t.Run("enabled but missing tenant id errors", func(t *testing.T) {
		m := map[string]string{"FIRST_TENANT_ENABLED": "true", "FIRST_TENANT_OWNER_EMAIL": "a@b.test"}
		seed, enabled, err := FirstTenantSeedFromEnv(getenvFrom(m), enq)
		if err == nil || !enabled || seed != nil {
			t.Fatalf("want (nil,true,err), got (%v,%v,%v)", seed, enabled, err)
		}
	})

	t.Run("enabled but missing owner email errors", func(t *testing.T) {
		m := map[string]string{"FIRST_TENANT_ENABLED": "true", "FIRST_TENANT_ID": "default"}
		seed, enabled, err := FirstTenantSeedFromEnv(getenvFrom(m), enq)
		if err == nil || !enabled || seed != nil {
			t.Fatalf("want (nil,true,err), got (%v,%v,%v)", seed, enabled, err)
		}
	})
}

// fakeManager is a minimal manager.Manager that records Add calls. Embedding the
// interface satisfies the type; only Add is exercised by SetupWithManager.
type fakeManager struct {
	manager.Manager
	addErr error
	added  []manager.Runnable
}

func (f *fakeManager) Add(r manager.Runnable) error {
	f.added = append(f.added, r)
	return f.addErr
}

func TestRegisterFirstTenantSeed(t *testing.T) {
	enq := &stubEnqueuer{}
	enabledEnv := func(k string) string {
		return map[string]string{
			"FIRST_TENANT_ENABLED":     "true",
			"FIRST_TENANT_ID":          "default",
			"FIRST_TENANT_OWNER_EMAIL": "admin@selfhosted.example.com",
		}[k]
	}

	t.Run("disabled: no runnable added, no error", func(t *testing.T) {
		mgr := &fakeManager{}
		if err := RegisterFirstTenantSeed(mgr, func(string) string { return "" }, enq, logr.Discard()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mgr.added) != 0 {
			t.Errorf("disabled seed must add nothing, added %d", len(mgr.added))
		}
	})

	t.Run("enabled: registers the seed runnable", func(t *testing.T) {
		mgr := &fakeManager{}
		if err := RegisterFirstTenantSeed(mgr, enabledEnv, enq, logr.Discard()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mgr.added) != 1 {
			t.Fatalf("want 1 runnable added, got %d", len(mgr.added))
		}
		if _, ok := mgr.added[0].(*FirstTenantSeedRunnable); !ok {
			t.Errorf("added runnable is not a *FirstTenantSeedRunnable: %T", mgr.added[0])
		}
	})

	t.Run("misconfigured: returns error", func(t *testing.T) {
		mgr := &fakeManager{}
		env := func(k string) string {
			return map[string]string{"FIRST_TENANT_ENABLED": "true"}[k] // no id/email
		}
		if err := RegisterFirstTenantSeed(mgr, env, enq, logr.Discard()); err == nil {
			t.Fatal("want error for missing identity")
		}
	})

	t.Run("manager rejects the runnable: propagates error", func(t *testing.T) {
		mgr := &fakeManager{addErr: errors.New("manager stopped")}
		if err := RegisterFirstTenantSeed(mgr, enabledEnv, enq, logr.Discard()); err == nil {
			t.Fatal("want error when mgr.Add fails")
		}
	})
}
