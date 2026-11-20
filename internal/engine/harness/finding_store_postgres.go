// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// PostgresFindingStore implements FindingStore on the findings table of the
// database of the tenant. The tenant ID that each call names selects the
// database.
type PostgresFindingStore struct {
	store *pgstore.Store
}

// NewPostgresFindingStore builds the store over the data pool. The function
// runs on first use, because the pool starts after the harness factory.
func NewPostgresFindingStore(pool pgstore.PoolFunc) *PostgresFindingStore {
	return &PostgresFindingStore{store: pgstore.New(pool)}
}

var _ FindingStore = (*PostgresFindingStore)(nil)

// Store writes the finding as one row of the findings table.
func (s *PostgresFindingStore) Store(ctx context.Context, tenantID string, missionID types.ID, f agent.Finding) error {
	enhanced := finding.NewEnhancedFinding(f, missionID, "")
	// A finding that an agent submits is raised by its mission run. A rerun of the
	// mission is the check that verifies the fix (ADR-0178).
	enhanced.Check = finding.ScanCheck(missionID)
	if err := s.store.Store(ctx, tenantID, enhanced); err != nil {
		return fmt.Errorf("store finding %s: %w", f.ID, err)
	}
	return nil
}

// Get returns the findings of the mission that match the filter.
func (s *PostgresFindingStore) Get(
	ctx context.Context, tenantID string, missionID types.ID, filter FindingFilter,
) ([]agent.Finding, error) {
	stored, err := s.store.List(ctx, tenantID, missionID, nil)
	if err != nil {
		return nil, fmt.Errorf("list findings of mission %s: %w", missionID, err)
	}
	out := make([]agent.Finding, 0, len(stored))
	for _, f := range stored {
		if filter.Matches(f.Finding) {
			out = append(out, f.Finding)
		}
	}
	return out, nil
}

// evidenceRejected reports that the store refused the evidence of a finding
// because an item is over the size limit.
func evidenceRejected(err error) bool {
	return errors.Is(err, finding.ErrEvidenceTooLarge)
}
