// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package fga_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// stubFGAClient is a minimal in-memory FGA stub for unit tests. It records
// Write calls and can be configured to return a specific error.
type stubFGAClient struct {
	written  []fga.Tuple
	writeErr error
}

func (s *stubFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}

func (s *stubFGAClient) Delete(_ context.Context, _ []fga.Tuple) error { return nil }
func (s *stubFGAClient) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) {
	return nil, nil
}
func (s *stubFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) { return false, nil }
func (s *stubFGAClient) Ping(_ context.Context) error                          { return nil }

func (s *stubFGAClient) tupleCount() int { return len(s.written) }

func (s *stubFGAClient) hasCanResolveTuple(enrollmentUID, tenantID string) bool {
	want := fga.SecretCanResolveTuple(enrollmentUID, tenantID)
	for _, t := range s.written {
		if t.User == want.User && t.Relation == want.Relation && t.Object == want.Object {
			return true
		}
	}
	return false
}

// ---- SecretCanResolveTuple shape tests ----

func TestSecretCanResolveTuple_Shape(t *testing.T) {
	got := fga.SecretCanResolveTuple("enrollment-abc123", "acme")
	if got.User != "plugin_principal:enrollment-abc123" {
		t.Errorf("User = %q, want %q", got.User, "plugin_principal:enrollment-abc123")
	}
	if got.Relation != "can_resolve" {
		t.Errorf("Relation = %q, want %q", got.Relation, "can_resolve")
	}
	if got.Object != "secret:tenant-acme:*" {
		t.Errorf("Object = %q, want %q", got.Object, "secret:tenant-acme:*")
	}
}

// ---- WriteSecretResolveGrant tests ----

func TestWriteSecretResolveGrant_WritesExactlyOneTuple(t *testing.T) {
	ctx := context.Background()
	stub := &stubFGAClient{}

	if err := fga.WriteSecretResolveGrant(ctx, stub, "enrollment-plugin-1", "tenant-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.tupleCount() != 1 {
		t.Fatalf("expected 1 tuple written, got %d", stub.tupleCount())
	}
	if !stub.hasCanResolveTuple("enrollment-plugin-1", "tenant-a") {
		t.Errorf("expected can_resolve tuple for enrollment-plugin-1 / tenant-a, got: %+v", stub.written)
	}
}

func TestWriteSecretResolveGrant_Idempotent_AlreadyExists(t *testing.T) {
	ctx := context.Background()
	stub := &stubFGAClient{
		writeErr: fmt.Errorf("fga 400: %w", clients.ErrAlreadyExists),
	}

	// Should return nil (idempotent) when tuple already exists.
	if err := fga.WriteSecretResolveGrant(ctx, stub, "enrollment-plugin-2", "tenant-b"); err != nil {
		t.Fatalf("expected nil for ErrAlreadyExists, got: %v", err)
	}
}

func TestWriteSecretResolveGrant_PropagatesOtherErrors(t *testing.T) {
	ctx := context.Background()
	wantErr := fmt.Errorf("fga 503: %w", clients.ErrUnreachable)
	stub := &stubFGAClient{writeErr: wantErr}

	err := fga.WriteSecretResolveGrant(ctx, stub, "enrollment-plugin-3", "tenant-c")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Errorf("expected ErrUnreachable in chain, got: %v", err)
	}
}

// ---- BackfillSecretResolveGrants tests ----

func TestBackfillSecretResolveGrants_WritesMissingTuples(t *testing.T) {
	ctx := context.Background()
	stub := &stubFGAClient{}

	plugins := []fga.PluginEnrollment{
		{EnrollmentUID: "enrollment-p1", TenantID: "tenant-x"},
		{EnrollmentUID: "enrollment-p2", TenantID: "tenant-y"},
	}

	results := fga.BackfillSecretResolveGrants(ctx, stub, plugins)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected error for %s: %v", r.EnrollmentUID, r.Err)
		}
		if !r.Written {
			t.Errorf("expected Written=true for %s", r.EnrollmentUID)
		}
	}
	if stub.tupleCount() != 2 {
		t.Fatalf("expected 2 tuples written, got %d", stub.tupleCount())
	}
}

func TestBackfillSecretResolveGrants_Idempotent_NoError(t *testing.T) {
	ctx := context.Background()
	// Simulate all tuples already existing.
	stub := &stubFGAClient{
		writeErr: fmt.Errorf("conflict: %w", clients.ErrAlreadyExists),
	}

	plugins := []fga.PluginEnrollment{
		{EnrollmentUID: "enrollment-p1", TenantID: "tenant-x"},
		{EnrollmentUID: "enrollment-p2", TenantID: "tenant-y"},
	}

	results := fga.BackfillSecretResolveGrants(ctx, stub, plugins)
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("expected nil error for already-existing tuple, got: %v", r.Err)
		}
		if r.Written {
			t.Errorf("expected Written=false for already-existing tuple %s", r.EnrollmentUID)
		}
	}
}

func TestBackfillSecretResolveGrants_ContinuesOnPerEnrollmentFailure(t *testing.T) {
	ctx := context.Background()

	// First Write succeeds, second fails. Use a stateful stub.
	callCount := 0
	stub := &countingFGAClient{
		onWrite: func(i int, _ []fga.Tuple) error {
			if i == 1 {
				return fmt.Errorf("transient: %w", clients.ErrUnreachable)
			}
			return nil
		},
	}
	_ = callCount

	plugins := []fga.PluginEnrollment{
		{EnrollmentUID: "enrollment-ok", TenantID: "tenant-ok"},
		{EnrollmentUID: "enrollment-fail", TenantID: "tenant-fail"},
		{EnrollmentUID: "enrollment-ok2", TenantID: "tenant-ok2"},
	}

	results := fga.BackfillSecretResolveGrants(ctx, stub, plugins)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	// First result: success.
	if results[0].Err != nil || !results[0].Written {
		t.Errorf("result[0] unexpected: err=%v written=%v", results[0].Err, results[0].Written)
	}
	// Second result: error.
	if results[1].Err == nil {
		t.Error("result[1]: expected error, got nil")
	}
	if !errors.Is(results[1].Err, clients.ErrUnreachable) {
		t.Errorf("result[1]: expected ErrUnreachable, got: %v", results[1].Err)
	}
	// Third result: success.
	if results[2].Err != nil || !results[2].Written {
		t.Errorf("result[2] unexpected: err=%v written=%v", results[2].Err, results[2].Written)
	}
}

func TestBackfillSecretResolveGrants_Empty(t *testing.T) {
	ctx := context.Background()
	stub := &stubFGAClient{}
	results := fga.BackfillSecretResolveGrants(ctx, stub, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil input, got %d", len(results))
	}
	if stub.tupleCount() != 0 {
		t.Errorf("expected 0 tuples written for nil input, got %d", stub.tupleCount())
	}
}

// countingFGAClient tracks call index to simulate per-call error injection.
type countingFGAClient struct {
	callIdx int
	onWrite func(i int, tuples []fga.Tuple) error
	written []fga.Tuple
}

func (c *countingFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	idx := c.callIdx
	c.callIdx++
	if c.onWrite != nil {
		if err := c.onWrite(idx, tuples); err != nil {
			return err
		}
	}
	c.written = append(c.written, tuples...)
	return nil
}

func (c *countingFGAClient) Delete(_ context.Context, _ []fga.Tuple) error { return nil }
func (c *countingFGAClient) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) {
	return nil, nil
}
func (c *countingFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
func (c *countingFGAClient) Ping(_ context.Context) error { return nil }
