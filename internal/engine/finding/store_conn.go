// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finding — store_conn.go
//
// ConnBoundFindingStore implements FindingStore using a tenant-bound *redis.Client.
// No tenant prefix is used; isolation is structural (audit C14/C15 closure).
// Get returns NotFound for IDs that don't exist in the connected tenant's DB —
// IDOR is impossible by construction (C15 closure).
package finding

import (
	"context"
	"encoding/json"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ConnBoundFindingStore implements FindingStore against a tenant-bound Redis client.
// All results are scoped to the calling tenant by the client itself (C14 closure).
type ConnBoundFindingStore struct {
	rdb *goredis.Client
}

// NewConnBoundFindingStore creates a FindingStore backed by the given tenant-bound client.
func NewConnBoundFindingStore(rdb *goredis.Client) *ConnBoundFindingStore {
	return &ConnBoundFindingStore{rdb: rdb}
}

// Key helpers — no tenant prefix (C14/C15 closure).

func cbFindingKey(id types.ID) string {
	return fmt.Sprintf("gibson:finding:%s", id)
}

func cbFindingMissionSetKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:finding:by_mission:%s", missionID)
}

func cbFindingSeveritySetKey(severity agent.FindingSeverity) string {
	return fmt.Sprintf("gibson:finding:by_severity:%s", string(severity))
}

// Store persists a finding and updates secondary indexes.
func (s *ConnBoundFindingStore) Store(ctx context.Context, finding EnhancedFinding) error {
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}
	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbFindingKey(finding.ID), "$", string(data))
	pipe.SAdd(ctx, cbFindingMissionSetKey(finding.MissionID), finding.ID.String())
	pipe.SAdd(ctx, cbFindingSeveritySetKey(finding.Severity), finding.ID.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Ensure ConnBoundFindingStore implements FindingStore at compile time.
var _ FindingStore = (*ConnBoundFindingStore)(nil)
