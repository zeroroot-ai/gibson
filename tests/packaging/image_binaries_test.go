// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package packaging guards the contract between the daemon image and the
// operational Jobs that run out of it (gibson#1302).
//
// A one-shot tool under cmd/ that a chart invokes has to be present in the
// image, and "present" is two independent lines in the Dockerfile: a build in
// the builder stage and a copy into the runtime stage. Missing either one is
// invisible in Go — the package compiles, its tests pass, `go build ./...`
// is green — and only shows up when the Job's container fails to start. For a
// pre-upgrade hook that means the whole `helm upgrade` aborts, which is worse
// than not having the Job at all.
//
// Pure unit: reads the Dockerfile and the cmd/ tree, no Docker.
package packaging

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// shippedTools lists the one-shot binaries the daemon image must carry
// alongside the daemon itself, each invoked by an explicit command override
// from a Job, DaemonSet, or Helm hook. Adding a tool here without adding it to
// the Dockerfile fails this test; shipping it in the Dockerfile without listing
// it here also fails, so the list cannot silently drift out of date.
var shippedTools = []string{
	"active-session-backfill",
	// bootstrap-tenant-owner (gibson#1103): a one-time, operator-credentialed
	// one-shot that creates the owner human identity for a tenant on a
	// closed-registration self-hosted install. No Helm hook — invoked ad hoc
	// via `kubectl exec` / a one-off Job, never wired into the standard
	// rollout.
	"bootstrap-tenant-owner",
	"gibson-migrate",
	"lowercase-tenant-owner",
	"sandbox-eviction-handler",
	"tenant-owner-backfill",
}

// repoRoot resolves the module root from this file: tests/packaging/ ⇒ two up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// readDockerfile returns the daemon image's Dockerfile as a string.
func readDockerfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "Dockerfile")
	b, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path, not user input
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestDaemonImageBuildsEveryShippedTool(t *testing.T) {
	dockerfile := readDockerfile(t)
	for _, tool := range shippedTools {
		t.Run(tool, func(t *testing.T) {
			want := "-o /out/" + tool + " ./cmd/" + tool
			if !strings.Contains(dockerfile, want) {
				t.Fatalf("Dockerfile has no builder-stage build for %s (looked for %q); "+
					"a Job invoking it would fail to start", tool, want)
			}
		})
	}
}

func TestDaemonImageCopiesEveryShippedToolIntoTheRuntimeStage(t *testing.T) {
	dockerfile := readDockerfile(t)
	for _, tool := range shippedTools {
		t.Run(tool, func(t *testing.T) {
			want := "COPY --from=builder /out/" + tool + " /usr/local/bin/" + tool
			if !strings.Contains(dockerfile, want) {
				t.Fatalf("Dockerfile builds %s but never copies it into the runtime stage "+
					"(looked for %q); the binary exists only in the discarded builder layer", tool, want)
			}
		})
	}
}

func TestEveryShippedToolHasACommandPackage(t *testing.T) {
	root := repoRoot(t)
	for _, tool := range shippedTools {
		t.Run(tool, func(t *testing.T) {
			dir := filepath.Join(root, "cmd", tool)
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("shipped tool %s has no cmd package at %s: %v", tool, dir, err)
			}
			if !info.IsDir() {
				t.Fatalf("%s is not a directory", dir)
			}
		})
	}
}

func TestShippedToolsListMatchesTheDockerfile(t *testing.T) {
	// The reverse direction: anything the Dockerfile copies into
	// /usr/local/bin must be declared above, so the list stays the readable
	// answer to "what is in this image, and why".
	dockerfile := readDockerfile(t)
	declared := make(map[string]bool, len(shippedTools))
	for _, tool := range shippedTools {
		declared[tool] = true
	}
	// The daemon itself is the image's ENTRYPOINT, not a one-shot tool.
	declared["gibson"] = true

	const prefix = "COPY --from=builder /out/"
	for _, line := range strings.Split(dockerfile, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		name := filepath.Base(fields[len(fields)-1])
		if !declared[name] {
			t.Errorf("Dockerfile ships %q but it is not in shippedTools; add it (with a note "+
				"on what invokes it) so the image contents stay documented", name)
		}
	}
}
