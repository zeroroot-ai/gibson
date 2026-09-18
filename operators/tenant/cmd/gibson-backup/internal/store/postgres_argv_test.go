// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSplitDSNPassword proves the password leaves the DSN and nothing else
// in the DSN moves.
func TestSplitDSNPassword(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, dsn, wantDSN, wantPass string
		wantErr                      bool
	}{
		{name: "password removed", dsn: "postgres://gibson:s3cr%40t@pg.ns.svc:5432/tenant_a?sslmode=require",
			wantDSN: "postgres://gibson@pg.ns.svc:5432/tenant_a?sslmode=require", wantPass: "s3cr@t"},
		{name: "postgresql scheme", dsn: "postgresql://u:p@h/db", wantDSN: "postgresql://u@h/db", wantPass: "p"},
		{name: "no password passes through", dsn: "postgres://gibson@pg:5432/db", wantDSN: "postgres://gibson@pg:5432/db"},
		{name: "no userinfo passes through", dsn: "postgres://pg:5432/db", wantDSN: "postgres://pg:5432/db"},
		{name: "not a url", dsn: "host=pg user=u password=p dbname=db", wantErr: true},
		{name: "unparseable url", dsn: "postgres://a b/db", wantErr: true},
		{name: "wrong scheme", dsn: "mysql://u:p@h/db", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotDSN, gotPass, err := splitDSNPassword(tc.dsn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got dsn %q pass %q", gotDSN, gotPass)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotDSN != tc.wantDSN || gotPass != tc.wantPass {
				t.Fatalf("got (%q, %q), want (%q, %q)", gotDSN, gotPass, tc.wantDSN, tc.wantPass)
			}
		})
	}
}

// TestPgCommandKeepsPasswordOffArgv is the finding's fixture: the argv of
// pg_dump and pg_restore never contains the password, and the child's
// environment carries it as PGPASSWORD.
func TestPgCommandKeepsPasswordOffArgv(t *testing.T) {
	t.Parallel()
	const dsn = "postgres://gibson:hunter2@pg:5432/tenant_a?sslmode=require"

	dump, err := pgCommand(context.Background(), "pg_dump", dsn, false, "--format=custom", "--no-password")
	if err != nil {
		t.Fatalf("pgCommand: %v", err)
	}
	if got := strings.Join(dump.Args, " "); strings.Contains(got, "hunter2") {
		t.Fatalf("pg_dump argv carries the password: %q", got)
	}
	if dump.Args[len(dump.Args)-1] != "postgres://gibson@pg:5432/tenant_a?sslmode=require" {
		t.Fatalf("pg_dump last arg = %q", dump.Args[len(dump.Args)-1])
	}
	if !hasEnv(dump.Env, "PGPASSWORD=hunter2") {
		t.Fatalf("pg_dump env lacks PGPASSWORD: %v", dump.Env)
	}

	restore, err := pgCommand(context.Background(), "pg_restore", dsn, true, "--no-password")
	if err != nil {
		t.Fatalf("pgCommand: %v", err)
	}
	args := restore.Args
	if strings.Contains(strings.Join(args, " "), "hunter2") {
		t.Fatalf("pg_restore argv carries the password: %q", args)
	}
	if args[len(args)-2] != "--dbname" || args[len(args)-1] != "postgres://gibson@pg:5432/tenant_a?sslmode=require" {
		t.Fatalf("pg_restore tail = %q", args[len(args)-2:])
	}
	if !hasEnv(restore.Env, "PGPASSWORD=hunter2") {
		t.Fatalf("pg_restore env lacks PGPASSWORD: %v", restore.Env)
	}

	// No password: the environment is left alone.
	plain, err := pgCommand(context.Background(), "pg_dump", "postgres://gibson@pg:5432/db", false)
	if err != nil {
		t.Fatalf("pgCommand: %v", err)
	}
	if plain.Env != nil {
		t.Fatalf("env set with no password: %v", plain.Env)
	}

	// An unparseable DSN never reaches a process.
	if _, err := pgCommand(context.Background(), "pg_dump", "host=pg password=p", false); err == nil {
		t.Fatal("want error for a non-URL dsn")
	}
}

func hasEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

// fakePg puts a shell script named name on PATH. The script writes its argv
// and PGPASSWORD to the file at recordPath, emits body on stdout, and exits
// with code.
func fakePg(t *testing.T, name, recordPath, body string, code int) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > " + recordPath + "\nprintf 'PGPASSWORD=%s\\n' \"$PGPASSWORD\" >> " + recordPath + "\n" +
		"printf '%s' '" + body + "'\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil { //nolint:gosec // the fake client must be executable; t.TempDir() path
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestPostgresBackupAndRestoreWithFakeClient runs both functions against a
// scripted pg_dump and pg_restore. The fixture: the script sees the password
// in PGPASSWORD and never on its argv.
func TestPostgresBackupAndRestoreWithFakeClient(t *testing.T) {
	const dsn = "postgres://gibson:hunter2@pg:5432/tenant_a?sslmode=require"
	rec := filepath.Join(t.TempDir(), "argv")

	fakePg(t, "pg_dump", rec, "dumpbytes", 0)
	var buf bytes.Buffer
	n, sum, err := PostgresBackup(context.Background(), dsn, &buf)
	if err != nil {
		t.Fatalf("PostgresBackup: %v", err)
	}
	if n != int64(len("dumpbytes")) || buf.String() != "dumpbytes" {
		t.Fatalf("copied %d bytes %q", n, buf.String())
	}
	want := sha256.Sum256([]byte("dumpbytes"))
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 = %s", sum)
	}
	seen, _ := os.ReadFile(rec) //nolint:gosec // t.TempDir() path
	if strings.Contains(string(seen), "hunter2@") || !strings.Contains(string(seen), "PGPASSWORD=hunter2") {
		t.Fatalf("pg_dump saw: %q", seen)
	}
	if !strings.Contains(string(seen), "postgres://gibson@pg:5432/tenant_a?sslmode=require") {
		t.Fatalf("pg_dump argv lacks the stripped dsn: %q", seen)
	}

	fakePg(t, "pg_restore", rec, "", 0)
	if err := PostgresRestore(context.Background(), dsn, strings.NewReader("archive")); err != nil {
		t.Fatalf("PostgresRestore: %v", err)
	}
	seen, _ = os.ReadFile(rec) //nolint:gosec // t.TempDir() path
	if strings.Contains(string(seen), "hunter2@") || !strings.Contains(string(seen), "PGPASSWORD=hunter2") {
		t.Fatalf("pg_restore saw: %q", seen)
	}
	if !strings.Contains(string(seen), "--dbname postgres://gibson@pg:5432/tenant_a?sslmode=require") {
		t.Fatalf("pg_restore argv lacks --dbname with the stripped dsn: %q", seen)
	}

	// A failing client surfaces as an error from both functions.
	fakePg(t, "pg_dump", rec, "", 3)
	if _, _, err := PostgresBackup(context.Background(), dsn, &buf); err == nil {
		t.Fatal("want pg_dump failure")
	}
	fakePg(t, "pg_restore", rec, "boom", 3)
	if err := PostgresRestore(context.Background(), dsn, strings.NewReader("archive")); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want pg_restore failure with its output, got %v", err)
	}

	// An unparseable DSN stops before the client runs.
	fakePg(t, "pg_dump", rec, "", 0)
	if _, _, err := PostgresBackup(context.Background(), "postgres://a b/db", &buf); err == nil {
		t.Fatal("want dsn parse error from PostgresBackup")
	}
	if err := PostgresRestore(context.Background(), "host=pg password=p", nil); err == nil {
		t.Fatal("want dsn error from PostgresRestore")
	}
}
