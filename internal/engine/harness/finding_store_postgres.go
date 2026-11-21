// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
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
	enhanced.Check = SubmittedFindingCheck(f, missionID)
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

// SubmittedFindingCheck is the check that raised a finding that an agent
// submits (ADR-0178, review m2). A finding that names the daemon record of a
// read of a connector tool was raised by that read: the check is the tool, and
// its ref is the id of the tool. Any other finding was raised by its mission
// run, and a rerun of the mission is the check. The tool comes from the record
// of the daemon, never from a field that the agent sets.
func SubmittedFindingCheck(f agent.Finding, missionID types.ID) finding.Check {
	for _, ev := range f.Evidence {
		if ev.GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_RECORDED {
			continue
		}
		if tool := ev.GetMetadata()["tool_name"]; strings.HasPrefix(tool, "mcp:") {
			return finding.Check{Kind: finding.CheckTool, Ref: tool}
		}
	}
	return finding.ScanCheck(missionID)
}
