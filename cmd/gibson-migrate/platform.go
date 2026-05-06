// Copyright 2026 Zero Day AI.
// Licensed under the Apache License, Version 2.0 (the "License").
//
// platform.go — `gibson-migrate platform {up|down|status}` subcommand.
// Applies the embedded Platform migration set (pkg/platform/migrations)
// against the dashboard / control-plane Postgres database identified by
// PLATFORM_POSTGRES_DSN.
//
// Spec: gibson-postgres-migrations Requirement 2.4 + design Component 3.

package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/lib/pq"

	pgmigrations "github.com/zero-day-ai/gibson/pkg/platform/migrations"
)

// platformDSNEnv is the env var the chart's platform-db-migrate Job sets.
const platformDSNEnv = "PLATFORM_POSTGRES_DSN"

// defaultPingTimeout caps the connectivity probe before opening migrations.
const defaultPingTimeout = 5 * time.Second

// runPlatform handles `gibson-migrate platform <action>`.
func runPlatform(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: usage: gibson-migrate platform {up|down|status}")
		return 1
	}
	action := args[0]
	rest := args[1:]

	dsn := os.Getenv(platformDSNEnv)
	if dsn == "" {
		fmt.Fprintf(stderr, "error: %s env var required\n", platformDSNEnv)
		return 1
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(stderr, "error: open platform DB: %v\n", err)
		return 1
	}
	defer db.Close()

	pingCtx, cancel := context.WithTimeout(ctx, defaultPingTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		fmt.Fprintf(stderr, "error: ping platform DB: %v\n", err)
		return 1
	}

	// Stamp legacy state if present so existing kind / dev clusters
	// don't try to re-apply migrations the chart's old psql Job
	// already executed.
	if err := pgmigrations.Stamp(ctx, db, pgmigrations.KindPlatform); err != nil {
		fmt.Fprintf(stderr, "error: stamp legacy state: %v\n", err)
		return 1
	}

	src, err := pgmigrations.NewPlatformSource()
	if err != nil {
		fmt.Fprintf(stderr, "error: platform source: %v\n", err)
		return 1
	}
	defer src.Close()

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil {
		fmt.Fprintf(stderr, "error: postgres migrate driver: %v\n", err)
		return 1
	}

	m, err := migrate.NewWithInstance("iofs", src, "platform", driver)
	if err != nil {
		fmt.Fprintf(stderr, "error: migrate instance: %v\n", err)
		return 1
	}

	switch action {
	case "up":
		return platformUp(m, stdout, stderr)
	case "status":
		return platformStatus(m, stdout, stderr)
	case "down":
		return platformDown(m, rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown platform action %q\n", action)
		return 1
	}
}

func platformUp(m *migrate.Migrate, stdout, _ io.Writer) int {
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		fmt.Fprintf(stdout, "platform up failed: %v\n", err)
		return 1
	}
	v, dirty, _ := m.Version()
	fmt.Fprintf(stdout, "platform up complete: version=%d dirty=%v\n", v, dirty)
	return 0
}

func platformStatus(m *migrate.Migrate, stdout, stderr io.Writer) int {
	v, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		fmt.Fprintf(stderr, "error: read version: %v\n", err)
		return 1
	}
	max, _ := pgmigrations.PlatformMaxVersion()
	fmt.Fprintf(stdout, "platform: current_version=%d dirty=%v latest_embedded=%d\n", v, dirty, max)
	return 0
}

func platformDown(m *migrate.Migrate, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("platform down", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.Uint("to", 0, "rollback target version (required)")
	confirm := fs.Bool("confirm", false, "explicit confirmation that destructive rollback is intended")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *to == 0 {
		fmt.Fprintln(stderr, "error: --to <version> is required")
		return 1
	}
	if !*confirm {
		fmt.Fprintln(stderr, "error: --confirm is required for down migrations")
		return 1
	}
	if err := m.Migrate(*to); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		fmt.Fprintf(stderr, "platform down failed: %v\n", err)
		return 1
	}
	v, dirty, _ := m.Version()
	fmt.Fprintf(stdout, "platform down complete: version=%d dirty=%v\n", v, dirty)
	return 0
}
