//go:build e2e
// +build e2e

// Package helpers — route_iterator.go implements the manifest-driven route
// iteration per design Component 3.
//
// RunOne drives a single route through its assertions (navigate → landmark →
// console-error → perf-budget) and returns a typed RouteResult.
//
// RunAll fans out across all entries with bounded concurrency and returns the
// complete result set in input order.
//
// Iteration intent is recorded here; execution is driven by the Playwright
// spec (dashboard-smoke.spec.ts). The iterator writes a per-route JSON
// report that the Playwright spec reads — this Go side consumes the final
// report written by Playwright.
//
// Requirements: R1.2, R1.3, R1.4, R7.1.
package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// RouteResult — single route's outcome
// ---------------------------------------------------------------------------

// RouteResult holds the outcome of a single route assertion run.
type RouteResult struct {
	// Path is the manifest route path.
	Path string `json:"path"`

	// OK is true if all assertions passed for this route.
	OK bool `json:"ok"`

	// HTTPStatus is the HTTP response status code.
	HTTPStatus int `json:"httpStatus"`

	// LoadTimeMs is the wall-clock time for the page/endpoint to respond.
	LoadTimeMs int64 `json:"loadTimeMs"`

	// LandmarkVisible is true if the landmark CSS selector/text was found
	// in the response (for kind=page routes only).
	LandmarkVisible bool `json:"landmarkVisible"`

	// ConsoleErrors is the list of JavaScript console Error messages captured
	// after allowlist filtering.
	ConsoleErrors []string `json:"consoleErrors"`

	// ShapeError is a human-readable string if JSON shape validation failed
	// for kind=api or kind=action routes with a shape_schema.
	ShapeError string `json:"shapeError"`

	// ScreenshotPath is the filesystem path of a failure screenshot (PNG).
	// Empty if the route passed.
	ScreenshotPath string `json:"screenshotPath"`

	// ColdCache is true if this was the first iteration of this route (the
	// perf budget is doubled per R7.2 for the first cold-cache iteration).
	ColdCache bool `json:"coldCache"`

	// PerfBudgetMs is the perf budget from the manifest (possibly doubled for
	// cold-cache iterations).
	PerfBudgetMs int64 `json:"perfBudgetMs"`

	// Error holds any infrastructure-level error (e.g., Playwright crash).
	Error string `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// RunOne — single route execution
// ---------------------------------------------------------------------------

// RunOne drives a single route assertion. Since Playwright runs in a separate
// process (the spec writes a JSON report), RunOne on the Go side is a thin
// wrapper that:
//  1. Validates the manifest entry.
//  2. Computes the effective perf budget (with cold-cache doubling per R7.2).
//  3. Returns an intent record that the caller can use to correlate with the
//     Playwright report.
//
// For full browser execution, see dashboard-smoke.spec.ts.
//
// Requirements: R1.2–R1.4, R7.1.
func RunOne(ctx context.Context, entry RouteEntry, coldCache bool) RouteResult {
	// Validate the entry before any execution attempt.
	if err := entry.Validate(); err != nil {
		return RouteResult{
			Path:  entry.Path,
			OK:    false,
			Error: fmt.Sprintf("route_iterator: RunOne: invalid manifest entry: %v", err),
		}
	}

	budget := int64(entry.PerfBudgetMs)
	if coldCache {
		budget *= 2 // R7.2: 2x tolerance for first cold-cache iteration
	}

	return RouteResult{
		Path:         entry.Path,
		ColdCache:    coldCache,
		PerfBudgetMs: budget,
		// OK, HTTPStatus, LoadTimeMs, etc. are populated by Playwright.
	}
}

// ---------------------------------------------------------------------------
// RunAll — fan-out with bounded concurrency
// ---------------------------------------------------------------------------

// RouteIteratorOptions configures a RunAll call.
type RouteIteratorOptions struct {
	// Concurrency is the number of parallel route iterations.
	// Defaults to 4 per design NFR Performance.
	Concurrency int

	// ColdCache marks the first iteration of each route as cold-cache
	// so the perf budget is doubled (R7.2).
	ColdCache bool
}

// RunAll drives all provided entries in parallel with bounded concurrency.
// Results are returned in the same order as the input entries (not arrival
// order). One failing route does NOT abort the others (R1.4 — fail-collect).
//
// Requirements: R1.4, NFR Performance.
func RunAll(ctx context.Context, entries []RouteEntry, opts RouteIteratorOptions) []RouteResult {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}

	results := make([]RouteResult, len(entries))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, entry := range entries {
		wg.Add(1)
		go func(idx int, e RouteEntry) {
			defer wg.Done()
			// Acquire semaphore slot.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = RouteResult{
					Path:  e.Path,
					OK:    false,
					Error: "context cancelled before execution",
				}
				return
			}
			defer func() { <-sem }()

			results[idx] = RunOne(ctx, e, opts.ColdCache)
		}(i, entry)
	}

	wg.Wait()
	return results
}

// ---------------------------------------------------------------------------
// LoadSmokeReport — read the Playwright-written JSON report
// ---------------------------------------------------------------------------

// SmokeRouteReport is the per-route JSON schema written by the Playwright
// spec and read by the Go smoke test. It mirrors RouteSmokResult in
// dashboard_smoke_test.go (kept here for the helper package boundary).
type SmokeRouteReport struct {
	Path           string   `json:"path"`
	OK             bool     `json:"ok"`
	HTTPStatus     int      `json:"httpStatus"`
	LoadTimeMs     int64    `json:"loadTimeMs"`
	LandmarkOK     bool     `json:"landmarkOk"`
	ConsoleErrors  []string `json:"consoleErrors"`
	ShapeError     string   `json:"shapeError"`
	ScreenshotPath string   `json:"screenshotPath"`
}

// SmokeReportFile is the top-level JSON written by dashboard-smoke.spec.ts.
type SmokeReportFile struct {
	Slug        string             `json:"slug"`
	TotalRoutes int                `json:"totalRoutes"`
	Passed      int                `json:"passed"`
	Failed      int                `json:"failed"`
	StartTime   time.Time          `json:"startTime"`
	EndTime     time.Time          `json:"endTime"`
	Results     []SmokeRouteReport `json:"results"`
}

// LoadSmokeReport reads the Playwright smoke JSON report from disk.
//
// The file path follows the convention: /tmp/dashboard-smoke-report-<slug>.json
// The slug is the tenant A slug used in the smoke run.
func LoadSmokeReport(path string) (*SmokeReportFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("route_iterator: LoadSmokeReport: read %s: %w", path, err)
	}
	var report SmokeReportFile
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("route_iterator: LoadSmokeReport: parse %s: %w", path, err)
	}
	return &report, nil
}

// ---------------------------------------------------------------------------
// SummarizeResults — produce a human-readable summary
// ---------------------------------------------------------------------------

// SummarizeResults returns a summary string listing failed routes.
// Returns empty string if all routes passed.
func SummarizeResults(results []SmokeRouteReport) string {
	var failures []string
	for _, r := range results {
		if !r.OK {
			line := fmt.Sprintf("  FAIL %s: http=%d landmark=%v consoleErrors=%d shape=%q",
				r.Path, r.HTTPStatus, r.LandmarkOK, len(r.ConsoleErrors), r.ShapeError)
			if r.ScreenshotPath != "" {
				line += fmt.Sprintf(" screenshot=%s", r.ScreenshotPath)
			}
			failures = append(failures, line)
		}
	}
	if len(failures) == 0 {
		return ""
	}
	out := fmt.Sprintf("route_iterator: %d route(s) failed:\n", len(failures))
	for _, f := range failures {
		out += f + "\n"
	}
	return out
}
