// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// TestSeedSystemBackplaneBaseline_WritesMissingTenantsOnly is the gibson#154
// fixture: two tenants registered under the platform, one already enabled on
// component:_system, one not. Exactly one tenant_enabled tuple is written.
func TestSeedSystemBackplaneBaseline_WritesMissingTenantsOnly(t *testing.T) {
	a := &recordingAuthorizer{
		listUsers: map[listUsersKey][]string{
			{ObjectType: "system_tenant", Object: "system_tenant:_system", Relation: "parent"}: {"tenant:primary", "tenant:acme"},
			{ObjectType: "component", Object: "component:_system", Relation: "tenant_enabled"}: {"tenant:acme"},
		},
	}
	n, err := SeedSystemBackplaneBaseline(context.Background(), a, slog.Default())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n != 1 || len(a.writes) != 1 {
		t.Fatalf("wrote %d tuples (%d reported), want 1: %+v", len(a.writes), n, a.writes)
	}
	want := authz.Tuple{User: "tenant:primary", Relation: "tenant_enabled", Object: "component:_system"}
	if a.writes[0] != want {
		t.Fatalf("wrote %+v, want %+v", a.writes[0], want)
	}
}

// TestSeedSystemBackplaneBaseline_ConvergedIsNoop: nothing to write once
// every registered tenant holds the baseline, and nothing to do with no
// tenants at all.
func TestSeedSystemBackplaneBaseline_ConvergedIsNoop(t *testing.T) {
	a := &recordingAuthorizer{
		listUsers: map[listUsersKey][]string{
			{ObjectType: "system_tenant", Object: "system_tenant:_system", Relation: "parent"}: {"tenant:primary"},
			{ObjectType: "component", Object: "component:_system", Relation: "tenant_enabled"}: {"primary"},
		},
	}
	if n, err := SeedSystemBackplaneBaseline(context.Background(), a, slog.Default()); err != nil || n != 0 || len(a.writes) != 0 {
		t.Fatalf("converged store: n=%d err=%v writes=%+v", n, err, a.writes)
	}
	empty := &recordingAuthorizer{}
	if n, err := SeedSystemBackplaneBaseline(context.Background(), empty, slog.Default()); err != nil || n != 0 || len(empty.writes) != 0 {
		t.Fatalf("no tenants: n=%d err=%v writes=%+v", n, err, empty.writes)
	}
}

type failingUsersAuthorizer struct {
	*recordingAuthorizer
	failList  bool
	failWrite bool
}

func (a *failingUsersAuthorizer) ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error) {
	if a.failList {
		return nil, errors.New("fga down")
	}
	return a.recordingAuthorizer.ListUsersOfType(ctx, objectType, object, relation, userType)
}

func (a *failingUsersAuthorizer) Write(ctx context.Context, tuples []authz.Tuple) error {
	if a.failWrite {
		return errors.New("write refused")
	}
	return a.recordingAuthorizer.Write(ctx, tuples)
}

func TestSeedSystemBackplaneBaseline_ErrorsPropagate(t *testing.T) {
	base := func() *recordingAuthorizer {
		return &recordingAuthorizer{listUsers: map[listUsersKey][]string{
			{ObjectType: "system_tenant", Object: "system_tenant:_system", Relation: "parent"}: {"tenant:primary"},
		}}
	}
	if _, err := SeedSystemBackplaneBaseline(context.Background(), &failingUsersAuthorizer{recordingAuthorizer: base(), failList: true}, slog.Default()); err == nil {
		t.Fatal("a failed enumeration must surface")
	}
	if _, err := SeedSystemBackplaneBaseline(context.Background(), &failingUsersAuthorizer{recordingAuthorizer: base(), failWrite: true}, slog.Default()); err == nil {
		t.Fatal("a failed write must surface")
	}
}

// countingAuthorizer guards the recording fake for the goroutine the runner
// spawns, and counts enumerations so a failing tick is visibly retried.
type countingAuthorizer struct {
	*recordingAuthorizer
	mu       sync.Mutex
	lists    int
	failList bool
}

func (a *countingAuthorizer) ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error) {
	a.mu.Lock()
	a.lists++
	fail := a.failList
	a.mu.Unlock()
	if fail {
		return nil, errors.New("fga down")
	}
	return a.recordingAuthorizer.ListUsersOfType(ctx, objectType, object, relation, userType)
}

func (a *countingAuthorizer) Write(ctx context.Context, tuples []authz.Tuple) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recordingAuthorizer.Write(ctx, tuples)
}

func (a *countingAuthorizer) counts() (lists, writes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lists, len(a.writes)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestRunSystemBackplaneBaseline_ConvergesNowAndOnEveryTick: the runner
// seeds at once, keeps ticking until the context ends, and a tick whose
// enumeration fails is retried on the next one rather than ending the loop.
func TestRunSystemBackplaneBaseline_ConvergesNowAndOnEveryTick(t *testing.T) {
	registered := map[listUsersKey][]string{
		{ObjectType: "system_tenant", Object: "system_tenant:_system", Relation: "parent"}: {"tenant:primary"},
	}

	a := &countingAuthorizer{recordingAuthorizer: &recordingAuthorizer{listUsers: registered}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunSystemBackplaneBaseline(ctx, a, 2*time.Millisecond, slog.Default())
		close(done)
	}()
	waitFor(t, "three ticks", func() bool { _, w := a.counts(); return w >= 3 })
	cancel()
	<-done

	failing := &countingAuthorizer{recordingAuthorizer: &recordingAuthorizer{listUsers: registered}, failList: true}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		RunSystemBackplaneBaseline(ctx, failing, 2*time.Millisecond, slog.Default())
		close(done)
	}()
	waitFor(t, "a retried failing tick", func() bool { l, _ := failing.counts(); return l >= 2 })
	cancel()
	<-done
	if _, w := failing.counts(); w != 0 {
		t.Fatalf("a failing enumeration must write nothing, wrote %d", w)
	}

	// A non-positive interval falls back to the default: the first tick
	// still runs at once and the loop ends with the context.
	once := &countingAuthorizer{recordingAuthorizer: &recordingAuthorizer{listUsers: registered}}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		RunSystemBackplaneBaseline(ctx, once, 0, slog.Default())
		close(done)
	}()
	waitFor(t, "the immediate tick", func() bool { _, w := once.counts(); return w == 1 })
	cancel()
	<-done
}
