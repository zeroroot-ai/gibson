// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package migrations

import (
	"context"
	"strings"
	"testing"
)

// TestRun_EmptyDSN locks the input-validation behaviour. The caller in
// cmd/main.go skips Run() entirely when pgDSN is empty (degraded
// dev-mode), but a defensive empty-DSN check inside Run() catches the
// case of a test or future caller that accidentally passes "".
func TestRun_EmptyDSN(t *testing.T) {
	err := Run(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error on empty DSN, got nil")
	}
	if !strings.Contains(err.Error(), "empty DSN") {
		t.Errorf("error must call out empty DSN; got %v", err)
	}
}

// TestRun_BadDSN exercises the dsn-parse + ping path without standing
// up a real Postgres. golang-migrate's parser is strict about scheme;
// a clearly-malformed DSN surfaces the wrap chain we expose to the
// operator log (helps the on-call read the failure quickly).
func TestRun_BadDSN(t *testing.T) {
	err := Run(context.Background(), "this-is-not-a-postgres-dsn")
	if err == nil {
		t.Fatalf("expected error on malformed DSN, got nil")
	}
	if !strings.Contains(err.Error(), "migrations:") {
		t.Errorf("error must be prefixed 'migrations:' for log searchability; got %v", err)
	}
}
