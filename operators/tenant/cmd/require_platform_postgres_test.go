/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"strings"
	"testing"
)

// TestRequirePlatformPostgres_MissingDSN_FailsLoud covers the
// one-code-path/198 contract: a missing DATAPLANE_PG_ADMIN_DSN must
// produce a structured error that names the missing env var. The
// startup gate ALWAYS fails — --dev-mode is irrelevant at this layer.
func TestRequirePlatformPostgres_MissingDSN_FailsLoud(t *testing.T) {
	getenv := func(string) string { return "" }
	err := requirePlatformPostgres(getenv)
	if err == nil {
		t.Fatal("expected non-nil error when DATAPLANE_PG_ADMIN_DSN is unset, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "DATAPLANE_PG_ADMIN_DSN") {
		t.Errorf("error message must name the missing env var DATAPLANE_PG_ADMIN_DSN; got: %s", msg)
	}
	if !strings.Contains(msg, "platform Postgres") {
		t.Errorf("error message must name the dependency \"platform Postgres\"; got: %s", msg)
	}
}

// TestRequirePlatformPostgres_DSNSet_Succeeds covers the happy path:
// when DATAPLANE_PG_ADMIN_DSN is set to any non-empty value, the gate
// returns nil and downstream wiring proceeds. The gate does NOT validate
// the DSN's syntactic correctness — that's the postgres client's job at
// connect time.
func TestRequirePlatformPostgres_DSNSet_Succeeds(t *testing.T) {
	getenv := func(k string) string {
		if k == "DATAPLANE_PG_ADMIN_DSN" {
			return "postgres://tenant_admin:secret@platform-postgres-rw.gibson.svc.cluster.local:5432/postgres?sslmode=disable"
		}
		return ""
	}
	if err := requirePlatformPostgres(getenv); err != nil {
		t.Errorf("expected nil error when DSN is set, got: %v", err)
	}
}

// TestRequirePlatformPostgres_EmptyStringDSN_FailsLoud guards against
// the common bug where an env var is defined but set to "" (e.g., from a
// helm `value: {{ .Values.x | default "" | quote }}` chain). An empty
// string MUST be treated as unset.
func TestRequirePlatformPostgres_EmptyStringDSN_FailsLoud(t *testing.T) {
	getenv := func(k string) string {
		if k == "DATAPLANE_PG_ADMIN_DSN" {
			return ""
		}
		return "something-else"
	}
	if err := requirePlatformPostgres(getenv); err == nil {
		t.Fatal("expected non-nil error when DSN is empty string, got nil")
	}
}

// TestRequirePlatformPostgres_EnvVarConst pins the const so a rename
// here triggers a test-level reminder to update the chart wiring and
// the migration playbook (deploy#208).
func TestRequirePlatformPostgres_EnvVarConst(t *testing.T) {
	if got, want := requirePlatformPostgresMissingEnv, "DATAPLANE_PG_ADMIN_DSN"; got != want {
		t.Errorf("env var name drifted: got %q want %q — sync the chart's "+
			"gibson-operators/templates/tenant-operator/deployment.yaml and the "+
			"one-code-path migration playbook before bumping this", got, want)
	}
}
