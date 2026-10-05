// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tenant_activation.go is the tenant activation signal (ADR-0060, D41).
//
// A component outside this repository sets tenant_status.activation through
// ConnectionPointService.SetTenantActivation. A suspended tenant cannot start
// a new mission. A tenant that no call has named, or that has no
// tenant_status row yet, is active: with no such component, each tenant is
// active when it exists.

const (
	activationActive    = "active"
	activationSuspended = "suspended"
)

// activationCacheTTL bounds how long a read of the activation is reused.
// SetTenantActivation drops the entry of its tenant at once.
const activationCacheTTL = 30 * time.Second

// activationCache holds recent reads of tenant_status.activation.
type activationCache struct {
	mu      sync.Mutex
	entries map[string]activationEntry
}

type activationEntry struct {
	suspended bool
	expires   time.Time
}

func (c *activationCache) get(tenant string, now time.Time) (suspended, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.entries[tenant]
	if !found || now.After(e.expires) {
		return false, false
	}
	return e.suspended, true
}

func (c *activationCache) put(tenant string, suspended bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]activationEntry)
	}
	c.entries[tenant] = activationEntry{suspended: suspended, expires: now.Add(activationCacheTTL)}
}

func (c *activationCache) forget(tenant string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenant)
}

// setTenantActivation writes the activation of a tenant that has a
// tenant_status row. found is false for a tenant with no row.
func setTenantActivation(ctx context.Context, db *sql.DB, tenantID, activation string) (changed, found bool, err error) {
	var before string
	err = db.QueryRowContext(ctx,
		`SELECT activation FROM tenant_status WHERE tenant_id = $1`, tenantID,
	).Scan(&before)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read activation: %w", err)
	}
	if before == activation {
		return false, true, nil
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE tenant_status SET activation = $2, updated_at = NOW() WHERE tenant_id = $1`,
		tenantID, activation,
	); err != nil {
		return false, true, fmt.Errorf("write activation: %w", err)
	}
	return true, true, nil
}

// listTenantIDs returns each tenant that has a tenant_status row.
func listTenantIDs(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT tenant_id FROM tenant_status ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return out, nil
}

// requireActiveTenant refuses new work for a suspended tenant. With no
// platform database, or no row for the tenant, the tenant is active. A read
// error is not a refusal: the gate must not stop work because the database
// had a blip, and the quota gates still apply.
func (s *DaemonServer) requireActiveTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return nil
	}
	now := time.Now()
	suspended, ok := s.tenantActivation.get(tenantID, now)
	if !ok {
		db := s.entitlementsDB()
		if db == nil {
			return nil
		}
		var activation string
		err := db.QueryRowContext(ctx,
			`SELECT activation FROM tenant_status WHERE tenant_id = $1`, tenantID,
		).Scan(&activation)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			activation = activationActive
		case err != nil:
			s.logger.WarnContext(ctx, "tenant activation read failed; treating the tenant as active",
				"tenant_id", tenantID, "error", err.Error())
			return nil
		}
		suspended = activation == activationSuspended
		s.tenantActivation.put(tenantID, suspended, now)
	}
	if suspended {
		return status.Errorf(codes.FailedPrecondition, "tenant %s is suspended; it cannot start new work", tenantID)
	}
	return nil
}
