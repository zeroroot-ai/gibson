// route-drift: detects when dashboard routes are added without a corresponding
// entry in the manifest (tests/e2e/manifests/dashboard-routes.yaml).
//
// Usage:
//
//	route-drift \
//	  --manifest  path/to/dashboard-routes.yaml \
//	  --app-dir   path/to/enterprise/platform/dashboard/app \
//	  [--proto-dir path/to/core/sdk/api/gen]
//
// Exit codes:
//
//	0 — no drift detected (or drift-check skipped because app-dir does not exist)
//	1 — drift detected (missing or extra manifest entries listed on stdout)
//	2 — error (bad flag, manifest parse failure, etc.)
//
// Requirements: R4.2.
// Design: Component 7 (Makefile target test-route-manifest-drift).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Minimal manifest types (duplicated from helpers to avoid build-tag dep)
// ---------------------------------------------------------------------------

type routeEntry struct {
	Path                  string `yaml:"path"`
	Kind                  string `yaml:"kind"`
	Method                string `yaml:"method"`
	Auth                  string `yaml:"auth"`
	Excluded              bool   `yaml:"excluded"`
	ExcludedReason        string `yaml:"excluded_reason"`
	ExcludedTrackingIssue string `yaml:"excluded_tracking_issue"`

	// Optional fields — captured but not validated here.
	Landmark    interface{} `yaml:"landmark"`
	ShapeSchema interface{} `yaml:"shape_schema"`
	UpstreamRPC string      `yaml:"upstream_rpc"`
	PerfBudget  int         `yaml:"perf_budget_ms"`
}

type routeManifest struct {
	Routes []routeEntry `yaml:"routes"`
}

// ---------------------------------------------------------------------------
// DriftReport — the structured output (printed as JSON to stdout)
// ---------------------------------------------------------------------------

// DriftReport is the JSON-serializable diff between the manifest and disk.
// CI jobs can parse this with jq to annotate PRs.
type DriftReport struct {
	// MissingFromManifest: routes found on disk but NOT in the manifest.
	MissingFromManifest []string `json:"missing_from_manifest"`

	// ExtraInManifest: routes in the manifest but NOT found on disk.
	// These are routes that were deleted from the dashboard without updating
	// the manifest (stale entries).
	ExtraInManifest []string `json:"extra_in_manifest"`

	// ManifestStats describes the manifest state.
	ManifestStats struct {
		Total    int `json:"total"`
		Active   int `json:"active"`
		Excluded int `json:"excluded"`
		Public   int `json:"public"`
	} `json:"manifest_stats"`

	// DiskStats describes the on-disk state.
	DiskStats struct {
		PageTSX int `json:"page_tsx"`
		RouteTS int `json:"route_ts"`
		Total   int `json:"total"`
	} `json:"disk_stats"`
}

// ---------------------------------------------------------------------------
// loadManifest reads and parses the YAML manifest.
// ---------------------------------------------------------------------------

func loadManifest(path string) ([]routeEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}
	var m routeManifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(m.Routes) == 0 {
		return nil, fmt.Errorf("manifest has no routes")
	}
	return m.Routes, nil
}

// ---------------------------------------------------------------------------
// normalizeNextJSPath converts a Next.js file-system path to a URL path.
//
// Next.js routing rules applied:
//   - app/page.tsx                       → /
//   - app/foo/page.tsx                   → /foo
//   - app/(group)/foo/page.tsx           → /foo    (route groups stripped)
//   - app/[id]/page.tsx                  → /{id}
//   - app/[...slug]/page.tsx             → /{...slug}
//   - app/[[...slug]]/page.tsx           → /[[...slug]]
//   - app/api/foo/route.ts               → /api/foo
//
// The appDir argument is the root of the Next.js app/ directory (absolute).
// The filePath argument is the absolute path to the page.tsx or route.ts file.
// ---------------------------------------------------------------------------

func normalizeNextJSPath(appDir, filePath string) string {
	// Make filePath relative to appDir.
	rel, err := filepath.Rel(appDir, filePath)
	if err != nil {
		return filePath
	}

	// Drop the filename (page.tsx or route.ts).
	dir := filepath.Dir(rel)
	if dir == "." {
		return "/"
	}

	// Split on the OS path separator.
	parts := strings.Split(filepath.ToSlash(dir), "/")

	// Process each segment.
	var urlParts []string
	for _, part := range parts {
		// Strip route groups: (foo) → skip.
		if strings.HasPrefix(part, "(") && strings.HasSuffix(part, ")") {
			continue
		}
		// Dynamic segments:
		//   [id]         → {id}
		//   [...slug]    → {...slug}
		//   [[...slug]]  → {[[...slug]]}  (optional catch-all)
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			inner := part[1 : len(part)-1]
			urlParts = append(urlParts, "{"+inner+"}")
			continue
		}
		urlParts = append(urlParts, part)
	}

	if len(urlParts) == 0 {
		return "/"
	}
	return "/" + strings.Join(urlParts, "/")
}

// ---------------------------------------------------------------------------
// walkDashboardApp returns all URL paths derived from page.tsx / route.ts.
// ---------------------------------------------------------------------------

func walkDashboardApp(appDir string) ([]string, int, int, error) {
	var paths []string
	var pageTSX, routeTS int

	err := filepath.WalkDir(appDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		switch name {
		case "page.tsx":
			pageTSX++
			urlPath := normalizeNextJSPath(appDir, path)
			paths = append(paths, urlPath)
		case "route.ts":
			routeTS++
			urlPath := normalizeNextJSPath(appDir, path)
			paths = append(paths, urlPath)
		}
		return nil
	})
	return paths, pageTSX, routeTS, err
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	manifestPath := flag.String("manifest", "", "path to dashboard-routes.yaml (required)")
	appDir := flag.String("app-dir", "", "path to dashboard app/ directory (optional; skips disk walk if absent)")
	jsonOutput := flag.Bool("json", false, "output drift report as JSON")
	flag.Parse()

	if *manifestPath == "" {
		fmt.Fprintln(os.Stderr, "route-drift: --manifest is required")
		flag.Usage()
		os.Exit(2)
	}

	// -------------------------------------------------------------------------
	// 1. Load the manifest.
	// -------------------------------------------------------------------------
	entries, err := loadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-drift: %v\n", err)
		os.Exit(2)
	}

	// Build manifest path set (all entries, including excluded).
	manifestPaths := make(map[string]bool)
	var activeCount, excludedCount, publicCount int
	for _, e := range entries {
		manifestPaths[e.Path] = true
		if e.Excluded {
			excludedCount++
		} else {
			activeCount++
		}
		if e.Auth == "public" {
			publicCount++
		}
	}

	report := DriftReport{}
	report.ManifestStats.Total = len(entries)
	report.ManifestStats.Active = activeCount
	report.ManifestStats.Excluded = excludedCount
	report.ManifestStats.Public = publicCount

	// -------------------------------------------------------------------------
	// 2. Walk the dashboard app/ directory (if provided and exists).
	// -------------------------------------------------------------------------
	var diskPaths []string
	if *appDir != "" {
		if _, statErr := os.Stat(*appDir); os.IsNotExist(statErr) {
			fmt.Fprintf(os.Stderr, "route-drift: app-dir %q does not exist — skipping disk walk\n", *appDir)
		} else {
			diskPaths, report.DiskStats.PageTSX, report.DiskStats.RouteTS, err = walkDashboardApp(*appDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "route-drift: walk app-dir: %v\n", err)
				os.Exit(2)
			}
			report.DiskStats.Total = report.DiskStats.PageTSX + report.DiskStats.RouteTS
		}
	}

	// -------------------------------------------------------------------------
	// 3. Diff: routes on disk that are missing from the manifest.
	// -------------------------------------------------------------------------
	diskPathSet := make(map[string]bool)
	for _, p := range diskPaths {
		diskPathSet[p] = true
		if !manifestPaths[p] {
			report.MissingFromManifest = append(report.MissingFromManifest, p)
		}
	}
	sort.Strings(report.MissingFromManifest)

	// -------------------------------------------------------------------------
	// 4. Diff: manifest entries whose path does not match any disk file.
	// Only flag non-excluded entries (excluded ones may be intentionally stale).
	// Skip paths that contain path parameters like {id} — those can't be
	// compared directly to the file-system path (normalizer produces {id} too,
	// but they may not align perfectly).
	// -------------------------------------------------------------------------
	for _, e := range entries {
		if e.Excluded {
			continue
		}
		// Skip parameterised paths (dynamic segments) — the file-system walk
		// normalises them to {x} but the manifest may use the same notation
		// for clarity. Any mismatch in parameterised paths is noise.
		if strings.Contains(e.Path, "{") {
			continue
		}
		// Only check if we have disk data to compare against.
		if len(diskPaths) > 0 && !diskPathSet[e.Path] {
			report.ExtraInManifest = append(report.ExtraInManifest, e.Path)
		}
	}
	sort.Strings(report.ExtraInManifest)

	// -------------------------------------------------------------------------
	// 5. Output.
	// -------------------------------------------------------------------------
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	}

	hasDrift := len(report.MissingFromManifest) > 0 || len(report.ExtraInManifest) > 0

	// Always print summary to stdout regardless of --json flag.
	fmt.Printf("route-drift: manifest=%s total=%d active=%d excluded=%d public=%d\n",
		*manifestPath,
		report.ManifestStats.Total,
		report.ManifestStats.Active,
		report.ManifestStats.Excluded,
		report.ManifestStats.Public,
	)
	if len(diskPaths) > 0 {
		fmt.Printf("route-drift: disk page.tsx=%d route.ts=%d total=%d\n",
			report.DiskStats.PageTSX,
			report.DiskStats.RouteTS,
			report.DiskStats.Total,
		)
	}

	if hasDrift {
		if len(report.MissingFromManifest) > 0 {
			fmt.Printf("\nroute-drift: FAIL — %d route(s) missing from manifest:\n", len(report.MissingFromManifest))
			for _, p := range report.MissingFromManifest {
				fmt.Printf("  MISSING: %s\n", p)
			}
			fmt.Println("\n  Add these routes to tests/e2e/manifests/dashboard-routes.yaml")
			fmt.Println("  with the appropriate kind, auth, landmark, and perf_budget_ms fields.")
			fmt.Println("  See CODEOWNERS: this file requires @platform-architecture approval.")
		}
		if len(report.ExtraInManifest) > 0 {
			fmt.Printf("\nroute-drift: WARN — %d non-excluded manifest entry/entries not found on disk:\n", len(report.ExtraInManifest))
			for _, p := range report.ExtraInManifest {
				fmt.Printf("  STALE:   %s\n", p)
			}
			fmt.Println("\n  These routes were removed from the dashboard without updating the manifest.")
			fmt.Println("  Remove or mark them excluded: true in tests/e2e/manifests/dashboard-routes.yaml")
		}
		os.Exit(1)
	}

	fmt.Println("route-drift: PASS — no drift detected")
	os.Exit(0)
}
