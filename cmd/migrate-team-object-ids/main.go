// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// migrate-team-object-ids is a one-shot migration binary that moves every
// legacy global team FGA object (`team:<id>`) into its owning tenant's
// namespace (`team:<tenant>/<id>`).
//
// Team object ids used to live in a namespace shared by every tenant, and
// `team.parent` is a plain [tenant] relation with no cardinality constraint, so
// two tenants could each parent the SAME team object — and every team RPC gates
// on that parent edge, so the second parent handed the squatter the victim's
// roster and, via `admin: [user] or admin from parent`, administration of it
// (gibson#1231). The daemon now derives the object id from the caller's own
// ext-authz tenant, which removes the shared namespace instead of guarding it.
// This binary brings the existing store to that shape.
//
// It reads STORED tuples, never effective ones — see
// internal/server/admin/team_object_migration.go for why that distinction is
// load-bearing. It is idempotent: teams already namespaced are counted and left
// alone, so a re-run after a partial failure finishes the job.
//
// Usage:
//
//	migrate-team-object-ids [-dry-run]
//
// Environment (same shape as the daemon's FGA config, and as the other
// one-shot backfill Jobs in cmd/):
//
//	EXT_AUTHZ_FGA_ADDR      — HTTP endpoint of the OpenFGA server
//	EXT_AUTHZ_FGA_STORE_ID  — FGA store ID
//	EXT_AUTHZ_FGA_MODEL_ID  — FGA authorization model ID
//
// Exits non-zero on any failure, so a Kubernetes Job retries rather than
// reporting a half-migrated store as success.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/server/admin"
)

func main() {
	dryRun := flag.Bool("dry-run", false,
		"read and report what would move, without writing or deleting any tuple")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	os.Exit(run(context.Background(), logger, os.Stdout, *dryRun))
}

// run does the whole job and returns the process exit code. It exists so that
// os.Exit is confined to main: os.Exit skips deferred functions, so calling it
// from the frame that defers authorizer.Close() would leak the FGA client's
// connection on every non-zero path.
//
// Exit codes: 0 migrated (or nothing to do), 1 failed, 2 finished but at least
// one id needs a human.
func run(ctx context.Context, logger *slog.Logger, stdout io.Writer, dryRun bool) int {
	cfg, err := fgaConfigFromEnv(logger)
	if err != nil {
		logger.Error("invalid FGA configuration", "err", err)
		return 1
	}

	authorizer, err := authz.NewFgaAuthorizer(ctx, cfg)
	if err != nil {
		logger.Error("failed to create FGA authorizer", "err", err)
		return 1
	}
	defer func() { _ = authorizer.Close() }()

	logger.Info("starting team object-id migration", "dry_run", dryRun)

	report, err := admin.MigrateTeamObjectIDs(ctx, authorizer, logger, dryRun)
	// The report is printed even on failure: a partial run has already written
	// namespaced copies, and the operator needs to know which.
	_, _ = fmt.Fprint(stdout, report.String())
	if err != nil {
		logger.Error("team object-id migration failed", "err", err)
		return 1
	}

	logger.Info("team object-id migration complete",
		"dry_run", dryRun,
		"tenants_scanned", report.TenantsScanned,
		"teams_migrated", len(report.TeamsMigrated),
		"teams_already_namespaced", report.TeamsAlreadyNamespaced,
		"squatted_ids", len(report.SquattedIDs),
		"skipped", len(report.Skipped),
	)
	if len(report.Skipped) > 0 {
		// Nothing was deleted for a skipped team, so the store is consistent —
		// but an id that cannot be namespaced needs a human, and a zero exit
		// would hide that.
		return 2
	}
	return 0
}

func fgaConfigFromEnv(logger *slog.Logger) (authz.FgaConfig, error) {
	addr := os.Getenv("EXT_AUTHZ_FGA_ADDR")
	storeID := os.Getenv("EXT_AUTHZ_FGA_STORE_ID")
	modelID := os.Getenv("EXT_AUTHZ_FGA_MODEL_ID")
	for name, v := range map[string]string{
		"EXT_AUTHZ_FGA_ADDR":     addr,
		"EXT_AUTHZ_FGA_STORE_ID": storeID,
		"EXT_AUTHZ_FGA_MODEL_ID": modelID,
	} {
		if v == "" {
			return authz.FgaConfig{}, fmt.Errorf("%s is required", name)
		}
	}
	return authz.FgaConfig{
		Endpoint:  addr,
		StoreID:   storeID,
		ModelID:   modelID,
		TimeoutMs: 5000,
		Logger:    logger,
	}, nil
}
