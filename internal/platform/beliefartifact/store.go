// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package beliefartifact keeps the belief artifact versions of each tenant
// (ADR-0106, gibson#788). The trainer of a tenant stores the two artifacts of
// one fit as one version through the daemon. The trainer holds no database
// credential.
package beliefartifact

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// The states of a version. The quality gate (gibson#789) moves a candidate to
// current or rejected. A current version that a newer one replaces is
// retired.
const (
	StateCandidate = "candidate"
	StateCurrent   = "current"
	StateRejected  = "rejected"
	StateRetired   = "retired"
)

// ErrNotJSONObject reports an artifact that is not a JSON object.
var ErrNotJSONObject = errors.New("beliefartifact: an artifact must be a JSON object")

// ErrNotACandidate reports a verdict on a version that is not a candidate.
var ErrNotACandidate = errors.New("beliefartifact: the version is not a candidate")

// Store reads and writes tenant_belief_artifacts.
type Store struct {
	db *sql.DB
}

// NewStore returns a Store over the platform database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Put stores both artifacts as the next version of the tenant, with the state
// candidate, and returns the version. Each artifact must be a JSON object. The
// version is one more than the highest version of the tenant; two concurrent
// writes for one tenant cannot get the same version, because the key refuses
// the second insert.
//
// Put writes the version string "tenant-<tenant>-v<version>" into the version
// field of both artifacts, so a stored artifact names the row that holds it.
// The trainer cannot know the number before the insert.
func (s *Store) Put(ctx context.Context, tenantID string, beliefModel, edgePosteriors []byte) (int64, error) {
	if tenantID == "" {
		return 0, errors.New("beliefartifact: Put: tenant is required")
	}
	for name, raw := range map[string][]byte{"belief_model": beliefModel, "edge_posteriors": edgePosteriors} {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return 0, fmt.Errorf("%w: %s", ErrNotJSONObject, name)
		}
	}
	const query = `
INSERT INTO tenant_belief_artifacts (tenant_id, version, belief_model, edge_posteriors)
SELECT $1, n.version,
       jsonb_set($2::jsonb, '{version}', to_jsonb('tenant-' || $1::text || '-v' || n.version::text)),
       jsonb_set($3::jsonb, '{version}', to_jsonb('tenant-' || $1::text || '-v' || n.version::text))
FROM  (SELECT COALESCE(MAX(version), 0) + 1 AS version
       FROM   tenant_belief_artifacts
       WHERE  tenant_id = $1) AS n
RETURNING version`
	var version int64
	if err := s.db.QueryRowContext(ctx, query, tenantID, string(beliefModel), string(edgePosteriors)).Scan(&version); err != nil {
		return 0, fmt.Errorf("beliefartifact: Put %s: %w", tenantID, err)
	}
	return version, nil
}

// Current returns the belief model of the current version of the tenant.
// found is false when the tenant has no current version.
func (s *Store) Current(ctx context.Context, tenantID string) (beliefModel []byte, version int64, found bool, err error) {
	const query = `
SELECT belief_model, version
FROM   tenant_belief_artifacts
WHERE  tenant_id = $1 AND state = 'current'`
	var model string
	err = s.db.QueryRowContext(ctx, query, tenantID).Scan(&model, &version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, 0, false, nil
	case err != nil:
		return nil, 0, false, fmt.Errorf("beliefartifact: Current %s: %w", tenantID, err)
	}
	return []byte(model), version, true, nil
}

// Verdict is the decision of the quality gate on one candidate version.
type Verdict struct {
	// Accepted makes the candidate current. Otherwise it is rejected.
	Accepted bool
	// BrierCandidate and BrierCurrent are the two scores on the settled
	// bets, and ScoredBets is the number of bets scored.
	BrierCandidate float64
	BrierCurrent   float64
	ScoredBets     int
}

// Decide records the verdict on a candidate version in one transaction. An
// accepted candidate becomes current, and the version it replaces is retired.
// A rejected candidate stays, marked rejected. Both keep the two scores.
func (s *Store) Decide(ctx context.Context, tenantID string, version int64, v Verdict) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beliefartifact: Decide %s v%d: begin: %w", tenantID, version, err)
	}
	defer func() { _ = tx.Rollback() }()

	state := StateRejected
	if v.Accepted {
		state = StateCurrent
		if _, err := tx.ExecContext(ctx, `
UPDATE tenant_belief_artifacts SET state = $2
WHERE  tenant_id = $1 AND state = $3`, tenantID, StateRetired, StateCurrent); err != nil {
			return fmt.Errorf("beliefartifact: Decide %s v%d: retire the current version: %w", tenantID, version, err)
		}
	}
	res, err := tx.ExecContext(ctx, `
UPDATE tenant_belief_artifacts
SET    state = $3, brier_candidate = $4, brier_current = $5, scored_bets = $6
WHERE  tenant_id = $1 AND version = $2 AND state = $7`,
		tenantID, version, state, v.BrierCandidate, v.BrierCurrent, v.ScoredBets, StateCandidate)
	if err != nil {
		return fmt.Errorf("beliefartifact: Decide %s v%d: %w", tenantID, version, err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("beliefartifact: Decide %s v%d: %w", tenantID, version, ErrNotACandidate)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("beliefartifact: Decide %s v%d: commit: %w", tenantID, version, err)
	}
	return nil
}
