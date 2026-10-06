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
	p := &pipelineProvisioner{cfg: PipelineConfig{Postgres: pg}}
	p.steps = p.buildSteps()
	err = p.steps[0].Provision(context.Background(), "acme", Limits{PostgresConnectionLimit: 7})
	if err == nil || !strings.Contains(err.Error(), "admin connect") {
		t.Fatalf("err = %v, want the Postgres provisioner's connect failure", err)
	}
}

// ensureRole creates a missing role and resets the password on an existing one.
func TestEnsureRole_CreatesOrAlters(t *testing.T) {
	conn := &fakeAdminConn{exists: false}
	if err := ensureRole(context.Background(), conn, "t_acme_app", "deadbeef"); err != nil {
		t.Fatalf("ensureRole (missing): %v", err)
	}
	if len(conn.execs) != 1 || conn.execs[0] != `CREATE ROLE "t_acme_app" WITH LOGIN PASSWORD 'deadbeef'` {
		t.Fatalf("execs = %q, want one CREATE ROLE", conn.execs)
	}

	conn = &fakeAdminConn{exists: true}
	if err := ensureRole(context.Background(), conn, "t_acme_app", "deadbeef"); err != nil {
		t.Fatalf("ensureRole (existing): %v", err)
	}
	if len(conn.execs) != 1 || conn.execs[0] != `ALTER ROLE "t_acme_app" WITH LOGIN PASSWORD 'deadbeef'` {
		t.Fatalf("execs = %q, want one ALTER ROLE", conn.execs)
	}
}

func TestEnsureRole_Errors(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		conn *fakeAdminConn
		want string
	}{
		"catalog check fails": {&fakeAdminConn{existsErr: boom}, "check role exists"},
		"create fails":        {&fakeAdminConn{exists: false, execErr: boom}, "create role"},
		"alter fails":         {&fakeAdminConn{exists: true, execErr: boom}, "alter role"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := ensureRole(context.Background(), tc.conn, "t_acme_app", "deadbeef")
			if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, boom) {
				t.Fatalf("err = %v, want %q wrapping boom", err, tc.want)
			}
		})
	}
}

// grantSchemaPrivileges issues the five grants in order and names a refused one.
func TestGrantSchemaPrivileges(t *testing.T) {
	conn := &fakeAdminConn{}
	if err := grantSchemaPrivileges(context.Background(), conn, "t_acme_app"); err != nil {
		t.Fatalf("grantSchemaPrivileges: %v", err)
	}
	if len(conn.execs) != 5 || conn.execs[0] != `GRANT USAGE ON SCHEMA public TO "t_acme_app"` {
		t.Fatalf("execs = %q, want five grants starting with USAGE ON SCHEMA", conn.execs)
	}
	for _, g := range conn.execs {
		if !strings.HasSuffix(g, `TO "t_acme_app"`) {
			t.Fatalf("grant %q does not name the role", g)
		}
	}

	boom := errors.New("boom")
	conn = &fakeAdminConn{execErr: boom}
	err := grantSchemaPrivileges(context.Background(), conn, "t_acme_app")
	if err == nil || !strings.Contains(err.Error(), "grant") || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the grant named and boom wrapped", err)
	}
}
