// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package store provides per-store backup and restore implementations.
// Each store exposes:
//
//	Backup(ctx, dsn string, w io.Writer) (size int64, sha256hex string, err error)
//	Restore(ctx, dsn string, r io.Reader) error
//
// The caller is responsible for wrapping w with an encrypting writer (see
// package envelope) before calling Backup so that data at rest in S3 is
// always encrypted.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os/exec"
)

// pgCommand builds a pg_dump or pg_restore command whose argv never carries
// the database password. The argv of any process is readable through
// /proc/<pid>/cmdline by every process in the same PID namespace and by
// every pod that can read the node's process table. The password leaves the
// DSN and reaches the client through PGPASSWORD on the child's environment,
// which only the child and root can read.
//
// The DSN is a URL (postgres://user:pass@host:port/db?opts). A DSN with no
// password passes through unchanged and the environment is untouched. The
// DSN itself is the last argument, or follows --dbname when dbnameFlag is set.
func pgCommand(ctx context.Context, name, dsn string, dbnameFlag bool, args ...string) (*exec.Cmd, error) {
	safeDSN, password, err := splitDSNPassword(dsn)
	if err != nil {
		return nil, err
	}
	if dbnameFlag {
		args = append(args, "--dbname", safeDSN)
	} else {
		args = append(args, safeDSN)
	}
	// #nosec G204 — name is a constant and the DSN is caller-controlled and validated upstream.
	cmd := exec.CommandContext(ctx, name, args...)
	if password != "" {
		cmd.Env = append(cmd.Environ(), "PGPASSWORD="+password)
	}
	return cmd, nil
}

// splitDSNPassword returns the DSN with its password removed, and the
// password on its own. A DSN that is not a URL is an error: the tool never
// guesses where a secret sits in a string it cannot parse.
func splitDSNPassword(dsn string) (safeDSN, password string, err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", "", fmt.Errorf("store/postgres: parse dsn: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", "", fmt.Errorf("store/postgres: dsn scheme %q is not postgres", u.Scheme)
	}
	if u.User == nil {
		return dsn, "", nil
	}
	password, ok := u.User.Password()
	if !ok {
		return dsn, "", nil
	}
	u.User = url.User(u.User.Username())
	return u.String(), password, nil
}

// PostgresBackup streams a pg_dump (custom format, -Fc) of the database
// identified by dsn into w.
//
// pg_dump must be available on PATH. For containerised deployments, the
// gibson-backup image must include postgresql-client.
//
// The function returns the total compressed bytes written to w and their
// SHA-256 hex digest. The caller wraps w with an encrypting writer so the
// SHA-256 is computed over the encrypted bytes; if a plaintext checksum is
// desired, pass a tee writer.
func PostgresBackup(ctx context.Context, dsn string, w io.Writer) (int64, string, error) {
	if _, err := exec.LookPath("pg_dump"); err != nil {
		return 0, "", fmt.Errorf("store/postgres: pg_dump not found on PATH: %w", err)
	}

	cmd, err := pgCommand(ctx, "pg_dump", dsn, false, "--format=custom", "--no-password")
	if err != nil {
		return 0, "", err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, "", fmt.Errorf("store/postgres: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return 0, "", fmt.Errorf("store/postgres: start pg_dump: %w", err)
	}

	h := sha256.New()
	tee := io.TeeReader(stdout, h)
	n, copyErr := io.Copy(w, tee)

	// Wait for pg_dump to exit regardless of copy error.
	if waitErr := cmd.Wait(); waitErr != nil {
		return n, "", fmt.Errorf("store/postgres: pg_dump failed: %w", waitErr)
	}
	if copyErr != nil {
		return n, "", fmt.Errorf("store/postgres: stream copy: %w", copyErr)
	}

	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// PostgresRestore restores a pg_dump custom-format backup from r into the
// database identified by dsn using pg_restore.
//
// pg_restore must be available on PATH. The database must already exist;
// this function does not CREATE DATABASE. For cross-tenant restores the caller
// must provision the target tenant first.
func PostgresRestore(ctx context.Context, dsn string, r io.Reader) error {
	if _, err := exec.LookPath("pg_restore"); err != nil {
		return fmt.Errorf("store/postgres: pg_restore not found on PATH: %w", err)
	}

	cmd, err := pgCommand(ctx, "pg_restore", dsn, true,
		"--no-password",
		"--clean",     // drop existing objects before restoring
		"--if-exists", // suppress errors for missing objects on --clean
		"--exit-on-error",
	)
	if err != nil {
		return err
	}
	cmd.Stdin = r

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("store/postgres: pg_restore failed: %w\noutput: %s", err, string(out))
	}
	return nil
}
