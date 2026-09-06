// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	dbpostgres "github.com/zeroroot-ai/gibson/internal/infra/database/postgres"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// TestTranslateSessionContextErr pins the sentinel mapping between the
// storage layer and the harness seam: the handler classifies conflicts
// (codes.Aborted) and size-cap refusals (codes.ResourceExhausted) purely via
// errors.Is on the harness sentinels, so this translation is load-bearing for
// the wire contract.
func TestTranslateSessionContextErr(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"nil passes through", nil, nil},
		{
			"storage conflict → harness conflict",
			fmt.Errorf("session context %q: %w", "s", dbpostgres.ErrSessionContextConflict),
			harness.ErrSessionContextConflict,
		},
		{
			"storage too-large → harness too-large",
			fmt.Errorf("cap: %w", dbpostgres.ErrSessionContextTooLarge),
			harness.ErrSessionContextTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := translateSessionContextErr(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("want nil, got %v", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("want errors.Is(%v, %v), got %v", got, tc.want, got)
			}
			// The original cause must remain inspectable.
			if !errors.Is(got, tc.in) && !errors.Is(got, errors.Unwrap(tc.in)) {
				t.Fatalf("translated error must preserve the storage cause; got %v", got)
			}
		})
	}

	// An unrelated error passes through untranslated.
	plain := errors.New("boom")
	if translateSessionContextErr(plain) != plain {
		t.Fatal("unrelated errors must pass through unchanged")
	}
}

// TestPoolSessionContextStore_NilPoolFailsPerCall pins the lazy-pool posture:
// wiring happens before the data-plane pool exists, and every call against a
// still-nil pool must fail cleanly (per-call error) rather than panic.
func TestPoolSessionContextStore_NilPoolFailsPerCall(t *testing.T) {
	s := newPoolSessionContextStore(func() datapool.Pool { return nil }, nil)

	if _, err := s.Put(context.Background(), "acme", "sess", []byte("x"), ""); err == nil {
		t.Error("Put with a nil pool must fail")
	}
	if _, _, err := s.Get(context.Background(), "acme", "sess"); err == nil {
		t.Error("Get with a nil pool must fail")
	}
	if err := s.Delete(context.Background(), "acme", "sess"); err == nil {
		t.Error("Delete with a nil pool must fail")
	}
}

// fakeBlobOps records calls and returns scripted results, standing in for
// datapool's SessionContextOps behind the store's ops seam.
type fakeBlobOps struct {
	putEtag string
	getData []byte
	getEtag string
	err     error
	calls   []string
}

func (f *fakeBlobOps) Put(_ context.Context, sessionID string, _ []byte, _ string) (string, error) {
	f.calls = append(f.calls, "put:"+sessionID)
	return f.putEtag, f.err
}

func (f *fakeBlobOps) Get(_ context.Context, sessionID string) ([]byte, string, error) {
	f.calls = append(f.calls, "get:"+sessionID)
	return f.getData, f.getEtag, f.err
}

func (f *fakeBlobOps) Delete(_ context.Context, sessionID string) error {
	f.calls = append(f.calls, "delete:"+sessionID)
	return f.err
}

func newTestSessionStore(pool datapool.Pool, ops sessionContextBlobOps) *poolSessionContextStore {
	s := newPoolSessionContextStore(func() datapool.Pool { return pool }, nil)
	s.ops = func(*datapool.Conn) sessionContextBlobOps { return ops }
	return s
}

// TestPoolSessionContextStore_RoutesThroughTenantConn covers the acquire →
// ops → translate path for all three verbs: the Conn is acquired for the
// caller's tenant, the ops see the session_id, and storage sentinels come
// back translated to the harness seam's sentinels.
func TestPoolSessionContextStore_RoutesThroughTenantConn(t *testing.T) {
	pool := &mockPool{conn: minimalConn()}
	ops := &fakeBlobOps{putEtag: "v1", getData: []byte("blob"), getEtag: "v1"}
	s := newTestSessionStore(pool, ops)

	etag, err := s.Put(context.Background(), "acme", "sess-1", []byte("blob"), "")
	if err != nil || etag != "v1" {
		t.Fatalf("Put: got (%q, %v)", etag, err)
	}
	data, etag, err := s.Get(context.Background(), "acme", "sess-1")
	if err != nil || string(data) != "blob" || etag != "v1" {
		t.Fatalf("Get: got (%q, %q, %v)", data, etag, err)
	}
	if err := s.Delete(context.Background(), "acme", "sess-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	want := []string{"put:sess-1", "get:sess-1", "delete:sess-1"}
	if len(ops.calls) != 3 || ops.calls[0] != want[0] || ops.calls[1] != want[1] || ops.calls[2] != want[2] {
		t.Fatalf("ops calls: want %v, got %v", want, ops.calls)
	}
}

func TestPoolSessionContextStore_TranslatesStorageSentinels(t *testing.T) {
	pool := &mockPool{conn: minimalConn()}

	conflictOps := &fakeBlobOps{err: fmt.Errorf("row: %w", dbpostgres.ErrSessionContextConflict)}
	s := newTestSessionStore(pool, conflictOps)
	if _, err := s.Put(context.Background(), "acme", "sess-1", []byte("x"), "stale"); !errors.Is(err, harness.ErrSessionContextConflict) {
		t.Fatalf("conflict must translate to the harness sentinel, got %v", err)
	}

	largeOps := &fakeBlobOps{err: fmt.Errorf("cap: %w", dbpostgres.ErrSessionContextTooLarge)}
	s = newTestSessionStore(pool, largeOps)
	if _, err := s.Put(context.Background(), "acme", "sess-1", []byte("x"), ""); !errors.Is(err, harness.ErrSessionContextTooLarge) {
		t.Fatalf("too-large must translate to the harness sentinel, got %v", err)
	}
}

func TestPoolSessionContextStore_PoolErrorsPropagate(t *testing.T) {
	pool := &mockPool{err: fmt.Errorf("tenant not provisioned")}
	s := newTestSessionStore(pool, &fakeBlobOps{})

	if _, err := s.Put(context.Background(), "acme", "sess", []byte("x"), ""); err == nil {
		t.Error("Put must surface a pool acquire failure")
	}
	if _, _, err := s.Get(context.Background(), "acme", "sess"); err == nil {
		t.Error("Get must surface a pool acquire failure")
	}
	if err := s.Delete(context.Background(), "acme", "sess"); err == nil {
		t.Error("Delete must surface a pool acquire failure")
	}

	// An unparseable tenant is refused before the pool is touched.
	s = newTestSessionStore(&mockPool{conn: minimalConn()}, &fakeBlobOps{})
	if _, err := s.Put(context.Background(), "", "sess", []byte("x"), ""); err == nil {
		t.Error("an empty tenant must be refused")
	}
}
