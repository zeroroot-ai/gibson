// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

// Shared FGA test stub plus the FGA-step absence contracts.
//
// E8/gibson#805 cutover: the DeleteTenantFGATuples teardown step was removed
// (FGA cleanup is now owned by the TenantGrants sub-CRD finalizer). The
// per-step DeleteTenantFGATuples contract tests went with it; the stubFGAClient
// is retained here because other contract tests in this package depend on it.

import (
	"context"
	"slices"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// ---------------------------------------------------------------------------
// Stub
// ---------------------------------------------------------------------------

// stubFGAClient is an in-memory fga.Client for tests. It records all Write
// and Delete calls; Read returns tuples stored in the written slice so that
// Delete-after-Read flows work correctly.
type stubFGAClient struct {
	written   []fga.Tuple
	deleted   []fga.Tuple
	writeErr  error
	readErr   error
	deleteErr error
	pingCalls int
}

func (s *stubFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}

func (s *stubFGAClient) Delete(_ context.Context, tuples []fga.Tuple) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, tuples...)
	// Remove deleted tuples from the written slice so subsequent reads
	// reflect the post-delete state (important for idempotency chains).
	remaining := s.written[:0]
	for _, w := range s.written {
		if !slices.Contains(tuples, w) {
			remaining = append(remaining, w)
		}
	}
	s.written = remaining
	return nil
}

func (s *stubFGAClient) Read(_ context.Context, filter fga.Tuple) ([]fga.Tuple, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	var out []fga.Tuple
	for _, t := range s.written {
		if (filter.User == "" || filter.User == t.User) &&
			(filter.Relation == "" || filter.Relation == t.Relation) &&
			(filter.Object == "" || filter.Object == t.Object) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *stubFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

func (s *stubFGAClient) Ping(_ context.Context) error {
	s.pingCalls++
	return nil
}

// ---------------------------------------------------------------------------
// Absence contracts
// ---------------------------------------------------------------------------

// TestWriteInitialFGATuples_AbsentFromProvisionSteps asserts that the
// WriteInitialFGATuples step no longer appears in ProvisionSteps. The step
// wrote a malformed FGA tuple (user:base64(email), relation=admin) that
// matched no real FGA principal (expected user:<numeric_zitadel_sub>).
// TenantMember.acceptInvitation already writes the correct tuple via
// spec.AcceptedByUserID; this test locks the removal (tenant-operator#215).
func TestWriteInitialFGATuples_AbsentFromProvisionSteps(t *testing.T) {
	t.Parallel()
	deps := ProvisionDeps{
		FGA:   &stubFGAClient{},
		Vault: &stubVaultAdmin{},
	}
	steps := ProvisionSteps(deps)
	for _, s := range steps {
		if s.Name() == "WriteInitialFGATuples" {
			t.Fatalf("WriteInitialFGATuples must not be present in ProvisionSteps (tenant-operator#215); full order: %s",
				namesOf(steps))
		}
	}
}

// TestDeleteTenantFGATuples_AbsentFromTeardownSteps locks the E8/gibson#805
// removal: FGA cleanup is now owned by the TenantGrants sub-CRD finalizer, so
// the inline DeleteTenantFGATuples teardown step must no longer appear in
// TeardownSteps.
func TestDeleteTenantFGATuples_AbsentFromTeardownSteps(t *testing.T) {
	t.Parallel()
	deps := ProvisionDeps{
		FGA:   &stubFGAClient{},
		Vault: &stubVaultAdmin{},
	}
	steps := TeardownSteps(deps)
	for _, s := range steps {
		if s.Name() == "DeleteTenantFGATuples" {
			t.Fatalf("DeleteTenantFGATuples must NOT be in TeardownSteps after E8/gibson#805; full order: %s",
				namesOf(steps))
		}
	}
}
