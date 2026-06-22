/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	gibsonmigrations "github.com/zeroroot-ai/gibson/migrations"
	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// fakeVersionReader returns canned schema versions and errors. Every
// test case constructs a fresh reader so package state does not leak
// across cases.
type fakeVersionReader struct {
	pgVersion uint
	pgErr     error
	neoVer    uint
	neoErr    error
}

func (f *fakeVersionReader) Postgres(_ context.Context, _ string) (uint, error) {
	return f.pgVersion, f.pgErr
}
func (f *fakeVersionReader) Neo4j(_ context.Context, _ string) (uint, error) {
	return f.neoVer, f.neoErr
}

// TestMigrationMetricEmitter_Emit drives the gauge through the five
// states the operator-side replacement must cover:
//
//   - Postgres current → 0
//   - Postgres behind  → 1
//   - Postgres probe error → gauge UNCHANGED (last-known)
//   - Neo4j current → 0
//   - Neo4j behind  → 1
//   - Neo4j unprovisioned (ErrTenantUnprovisioned) → gauge UNCHANGED
//
// The test asserts both that the new value lands and that an unrelated
// state (e.g. error path) does not clobber the previously-recorded
// value. This matches the daemon's old behaviour, where an unreachable
// tenant DB did not flip the metric to a misleading value.
func TestMigrationMetricEmitter_Emit(t *testing.T) {
	t.Parallel()

	latestPostgres, err := pgmigrations.TenantMaxVersion()
	if err != nil || latestPostgres == 0 {
		t.Fatalf("TenantMaxVersion: got (%d, %v); test assumes at least one tenant migration is embedded", latestPostgres, err)
	}
	latestNeo4j, err := gibsonmigrations.LatestNeo4jVersion()
	if err != nil || latestNeo4j == 0 {
		t.Fatalf("LatestNeo4jVersion: got (%d, %v); test assumes at least one neo4j migration is embedded", latestNeo4j, err)
	}

	cases := []struct {
		name       string
		reader     *fakeVersionReader
		wantPg     float64
		wantNeo    float64
		wantEmitOK bool
	}{
		{
			name:       "both_current",
			reader:     &fakeVersionReader{pgVersion: latestPostgres, neoVer: latestNeo4j},
			wantPg:     0,
			wantNeo:    0,
			wantEmitOK: true,
		},
		{
			name:       "both_behind",
			reader:     &fakeVersionReader{pgVersion: latestPostgres - 1, neoVer: latestNeo4j - 1},
			wantPg:     1,
			wantNeo:    1,
			wantEmitOK: true,
		},
		{
			name:       "postgres_behind_neo4j_current",
			reader:     &fakeVersionReader{pgVersion: 0, neoVer: latestNeo4j},
			wantPg:     1,
			wantNeo:    0,
			wantEmitOK: true,
		},
		{
			name:       "neo4j_unprovisioned_does_not_touch_gauge",
			reader:     &fakeVersionReader{pgVersion: latestPostgres, neoErr: ErrTenantUnprovisioned},
			wantPg:     0,
			wantNeo:    -1, // sentinel: skip neo4j assertion (gauge should not be set)
			wantEmitOK: true,
		},
		{
			name:       "postgres_probe_error_does_not_touch_gauge",
			reader:     &fakeVersionReader{pgErr: errors.New("simulated outage"), neoVer: latestNeo4j},
			wantPg:     -1, // sentinel: skip postgres assertion
			wantNeo:    0,
			wantEmitOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset gauge state so cases stay independent. Each case
			// uses a tenant ID derived from the case name to avoid
			// label collisions across subtests.
			metrics.MigrationPending.Reset()
			tenantID := "tenant-" + tc.name

			emitter := NewMigrationMetricEmitter(tc.reader)
			err := emitter.Emit(context.Background(), tenantID)
			gotOK := err == nil
			if gotOK != tc.wantEmitOK {
				t.Errorf("Emit returned err=%v; want ok=%v", err, tc.wantEmitOK)
			}

			if tc.wantPg >= 0 {
				gotPg := testutil.ToFloat64(metrics.MigrationPending.WithLabelValues(tenantID, "postgres"))
				if gotPg != tc.wantPg {
					t.Errorf("postgres gauge: got %v, want %v", gotPg, tc.wantPg)
				}
			} else {
				if hasPg := metricExists(tenantID, "postgres"); hasPg {
					t.Errorf("postgres gauge should not have been set, but is recorded")
				}
			}

			if tc.wantNeo >= 0 {
				gotNeo := testutil.ToFloat64(metrics.MigrationPending.WithLabelValues(tenantID, "neo4j"))
				if gotNeo != tc.wantNeo {
					t.Errorf("neo4j gauge: got %v, want %v", gotNeo, tc.wantNeo)
				}
			} else {
				if hasNeo := metricExists(tenantID, "neo4j"); hasNeo {
					t.Errorf("neo4j gauge should not have been set, but is recorded")
				}
			}
		})
	}
}

// metricExists returns true when (tenant, subsystem) has a value in the
// MigrationPending gauge. testutil.ToFloat64 returns 0 for both
// "metric never set" and "metric set to zero"; DeleteLabelValues
// disambiguates by reporting whether the labelset existed, and is
// safe here because each subtest does metrics.MigrationPending.Reset()
// at the start.
func metricExists(tenant, subsystem string) bool {
	return metrics.MigrationPending.DeleteLabelValues(tenant, subsystem)
}
