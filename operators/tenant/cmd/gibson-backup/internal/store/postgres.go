// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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
	"os/exec"
)

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

	// #nosec G204 — dsn is caller-controlled and validated upstream.
	cmd := exec.CommandContext(ctx, "pg_dump", "--format=custom", "--no-password", dsn)

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

	// #nosec G204 — dsn is caller-controlled and validated upstream.
	cmd := exec.CommandContext(ctx,
		"pg_restore",
		"--no-password",
		"--clean",     // drop existing objects before restoring
		"--if-exists", // suppress errors for missing objects on --clean
		"--exit-on-error",
		"--dbname", dsn,
	)
	cmd.Stdin = r

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("store/postgres: pg_restore failed: %w\noutput: %s", err, string(out))
	}
	return nil
}
