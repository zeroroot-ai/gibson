// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// A tenant's declared Postgres connection limit reaches the role as
// ALTER ROLE ... CONNECTION LIMIT N (gibson#545). Before this the field was
// published on the CRD and read by nothing, so a tenant meant to be capped
// was not.
func TestApplyConnectionLimit_TenantLimitWins(t *testing.T) {
	p := &pgProvisioner{cfg: PostgresConfig{DefaultConnectionLimit: 50}}
	conn := &fakeAdminConn{}

	if err := p.applyConnectionLimit(context.Background(), conn, "t_acme_app", Limits{PostgresConnectionLimit: 7}); err != nil {
		t.Fatalf("applyConnectionLimit: %v", err)
	}
	want := `ALTER ROLE "t_acme_app" CONNECTION LIMIT 7`
	if len(conn.execs) != 1 || conn.execs[0] != want {
		t.Fatalf("execs = %q, want exactly [%s]", conn.execs, want)
	}
}

// With no tenant limit the operator default applies, and with neither the
// role keeps the Postgres default.
func TestApplyConnectionLimit_DefaultAndNone(t *testing.T) {
	p := &pgProvisioner{cfg: PostgresConfig{DefaultConnectionLimit: 50}}
	conn := &fakeAdminConn{}
	if err := p.applyConnectionLimit(context.Background(), conn, "t_acme_app", Limits{}); err != nil {
		t.Fatalf("applyConnectionLimit: %v", err)
	}
	want := `ALTER ROLE "t_acme_app" CONNECTION LIMIT 50`
	if len(conn.execs) != 1 || conn.execs[0] != want {
		t.Fatalf("execs = %q, want exactly [%s]", conn.execs, want)
	}

	none := &pgProvisioner{cfg: PostgresConfig{}}
	conn = &fakeAdminConn{}
	if err := none.applyConnectionLimit(context.Background(), conn, "t_acme_app", Limits{}); err != nil {
		t.Fatalf("applyConnectionLimit: %v", err)
	}
	if len(conn.execs) != 0 {
		t.Fatalf("no limit anywhere must not ALTER the role, got %q", conn.execs)
	}
}

// LimitsFrom reads the TenantDataPlane resources block, and a nil block means
// the operator defaults.
func TestLimitsFrom(t *testing.T) {
	if got := LimitsFrom(nil); got != (Limits{}) {
		t.Fatalf("LimitsFrom(nil) = %+v, want zero", got)
	}
	got := LimitsFrom(&gibsonv1alpha1.TenantDataPlaneResources{PostgresConnectionLimit: 7})
	if got.PostgresConnectionLimit != 7 {
		t.Fatalf("LimitsFrom = %+v, want PostgresConnectionLimit 7", got)
	}
}

// A refused ALTER ROLE surfaces as the step's error, named.
func TestApplyConnectionLimit_ExecErrorSurfaces(t *testing.T) {
	p := &pgProvisioner{cfg: PostgresConfig{DefaultConnectionLimit: 50}}
	conn := &fakeAdminConn{execErr: errors.New("permission denied")}
	err := p.applyConnectionLimit(context.Background(), conn, "t_acme_app", Limits{})
	if err == nil || !strings.Contains(err.Error(), "set connection limit") {
		t.Fatalf("err = %v, want the connection-limit step named", err)
	}
}

// The Postgres step hands the limits to the Postgres provisioner. A
// provisioner with no reachable server fails at connect, which is enough to
// prove the step called it with the pipeline's limits rather than skipping.
func TestPipeline_PostgresStepCallsTheProvisioner(t *testing.T) {
	pg, err := NewPostgresProvisioner(PostgresConfig{AdminDSN: "postgres://nobody@127.0.0.1:1/postgres?connect_timeout=1", KEKDeriver: fixedKEKDeriver{}})
	if err != nil {
		t.Fatalf("NewPostgresProvisioner: %v", err)
	}
	p := New(PipelineConfig{Postgres: pg})
	err = p.steps[0].Provision(context.Background(), "acme", Limits{PostgresConnectionLimit: 7})
	if err == nil || !strings.Contains(err.Error(), "admin connect") {
		t.Fatalf("err = %v, want the Postgres provisioner's connect failure", err)
	}
}
