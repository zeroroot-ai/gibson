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
// current or rejected.
const (
	StateCandidate = "candidate"
	StateCurrent   = "current"
	StateRejected  = "rejected"
)

// ErrNotJSONObject reports an artifact that is not a JSON object.
var ErrNotJSONObject = errors.New("beliefartifact: an artifact must be a JSON object")

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
SELECT $1, COALESCE(MAX(version), 0) + 1, $2::jsonb, $3::jsonb
FROM   tenant_belief_artifacts
WHERE  tenant_id = $1
RETURNING version`
	var version int64
	if err := s.db.QueryRowContext(ctx, query, tenantID, string(beliefModel), string(edgePosteriors)).Scan(&version); err != nil {
		return 0, fmt.Errorf("beliefartifact: Put %s: %w", tenantID, err)
	}
	return version, nil
}
