// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TrainResult is the outcome of one offline training run.
type TrainResult struct {
	Version  string // the per-tenant version stamped, e.g. "tenant-acme-v3"
	Path     string // where the artifact was written
	Rows     int    // training rows extracted from the Timeline
	Artifact *Artifact
}

// TrainTenant fits a NEW versioned per-tenant belief model from a tenant's brain
// Timeline (auto-outcomes + HITL labels) and writes it to modelsDir (ADR-0006).
//
// basePath is the structural template (the OSS base-v1 artifact): the trainer
// reuses its variables + edges and refits every CPT from tenant data. The new
// artifact is versioned `tenant-<tenant>-v<n>` where n is one past the highest
// existing per-tenant version in modelsDir, so each run ships a fresh pinnable
// model and never overwrites a version a past mission pinned (ADR-0005 §5).
//
// tenant must be the SAME tenant whose Timeline `events` came from — the caller
// (the daemon's per-tenant Registry) guarantees this; the artifact is named for
// and usable by that tenant only. No cross-tenant pooling (ADR-0006 §6).
func TrainTenant(tenant string, events []brain.Event, basePath, modelsDir string) (*TrainResult, error) {
	if strings.TrimSpace(tenant) == "" {
		return nil, fmt.Errorf("braintrain: empty tenant")
	}
	base, err := LoadArtifact(basePath)
	if err != nil {
		return nil, err
	}

	known := map[string]bool{}
	for _, v := range base.Variables {
		known[v] = true
	}
	rows := RowsFromTimeline(events, known)

	version := NextVersion(modelsDir, tenant)
	trained, err := Fit(base, rows, version)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(modelsDir, 0o755); err != nil {
		return nil, fmt.Errorf("braintrain: create models dir: %w", err)
	}
	path := filepath.Join(modelsDir, version+".json")
	if err := trained.Write(path); err != nil {
		return nil, err
	}
	return &TrainResult{Version: version, Path: path, Rows: len(rows), Artifact: trained}, nil
}

// sanitizeTenant turns tenant into a filesystem/version-safe token, shared by
// every per-tenant artifact kind this package versions (the belief-CPT model,
// edge_posterior.go's per-edge-type Beta posteriors).
func sanitizeTenant(tenant string) string {
	return regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(tenant, "-")
}

// tenantVersionPrefix is the belief-CPT model's per-tenant artifact filename
// prefix. edge_posterior.go's edgePosteriorVersionPrefix is the distinct
// prefix for the OTHER artifact kind this package versions, so a `tenant-<id>-v`
// listing and a `tenant-<id>-edges-v` listing never collide in the same
// modelsDir.
func tenantVersionPrefix(tenant string) string {
	return "tenant-" + sanitizeTenant(tenant) + "-v"
}

// NextVersion scans modelsDir for existing `tenant-<id>-v<n>.json` artifacts and
// returns the next version string (one past the highest n; v1 if none). Past
// versions are NEVER reused, so a mission that pinned vN can always re-load it.
// Exported so the standalone belief-trainer CLI versions the same way TrainTenant does.
func NextVersion(modelsDir, tenant string) string {
	return nextVersionWithPrefix(modelsDir, tenantVersionPrefix(tenant))
}

// nextVersionWithPrefix scans modelsDir for existing `<prefix><n>.json`
// artifacts and returns the next version string (one past the highest n; 1
// if none) — the version-scanning logic shared by NextVersion (the
// belief-CPT model) and NextEdgePosteriorVersion (edge_posterior.go's
// per-edge-type Beta posteriors); the two differ only in which prefix they
// scan for.
func nextVersionWithPrefix(modelsDir, prefix string) string {
	highest := 0
	entries, _ := os.ReadDir(modelsDir) // missing dir → start at 1
	var nums []int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		numStr := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json")
		if n, err := strconv.Atoi(numStr); err == nil {
			nums = append(nums, n)
		}
	}
	sort.Ints(nums)
	if len(nums) > 0 {
		highest = nums[len(nums)-1]
	}
	return fmt.Sprintf("%s%d", prefix, highest+1)
}
