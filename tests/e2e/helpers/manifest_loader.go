//go:build e2e
// +build e2e

// Package helpers provides shared test infrastructure for the Gibson e2e suite.
// This file implements the route manifest loader per design Component 2.
//
// The manifest is `tests/e2e/manifests/dashboard-routes.yaml` — the single
// source of truth per R4.1. Every dashboard route (page.tsx and route.ts) MUST
// appear in this manifest; the drift guard (Task 4) enforces this at CI time.
//
// Requirements: R4.1, R4.2.
package helpers

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// RouteEntry — typed YAML schema per design Component 2
// ---------------------------------------------------------------------------

// RouteKind identifies whether a route is a full-page render, a JSON API
// endpoint, or a Server Action endpoint.
type RouteKind string

const (
	KindPage   RouteKind = "page"
	KindAPI    RouteKind = "api"
	KindAction RouteKind = "action"
)

// RouteAuth identifies whether a route requires authentication.
type RouteAuth string

const (
	AuthRequired RouteAuth = "required"
	AuthPublic   RouteAuth = "public"
)

// RouteEntry mirrors the YAML schema from the manifest.
// All YAML fields must be present in the file; unknown fields are rejected.
type RouteEntry struct {
	Path                    string    `yaml:"path"`
	Kind                    RouteKind `yaml:"kind"`
	Method                  string    `yaml:"method"`
	Auth                    RouteAuth `yaml:"auth"`
	Landmark                *string   `yaml:"landmark"`
	ShapeSchema             *string   `yaml:"shape_schema"`
	UpstreamRPC             string    `yaml:"upstream_rpc"`
	PerfBudgetMs            int       `yaml:"perf_budget_ms"`
	Excluded                bool      `yaml:"excluded"`
	ExcludedReason          string    `yaml:"excluded_reason"`
	ExcludedTrackingIssue   string    `yaml:"excluded_tracking_issue"`
}

// Validate checks that the RouteEntry has all required fields and valid values.
// Returns a non-nil error describing the first validation failure.
func (e RouteEntry) Validate() error {
	if e.Path == "" {
		return fmt.Errorf("manifest_loader: RouteEntry.path is required")
	}
	if !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("manifest_loader: RouteEntry.path %q must start with /", e.Path)
	}
	switch e.Kind {
	case KindPage, KindAPI, KindAction:
		// valid
	case "":
		return fmt.Errorf("manifest_loader: RouteEntry.kind is required for path %q", e.Path)
	default:
		return fmt.Errorf("manifest_loader: RouteEntry.kind %q is not valid for path %q — must be page|api|action", e.Kind, e.Path)
	}
	switch e.Auth {
	case AuthRequired, AuthPublic:
		// valid
	case "":
		return fmt.Errorf("manifest_loader: RouteEntry.auth is required for path %q", e.Path)
	default:
		return fmt.Errorf("manifest_loader: RouteEntry.auth %q is not valid for path %q — must be required|public", e.Auth, e.Path)
	}
	if e.Excluded && e.ExcludedReason == "" {
		return fmt.Errorf("manifest_loader: RouteEntry path %q has excluded=true but no excluded_reason", e.Path)
	}
	if e.PerfBudgetMs < 0 {
		return fmt.Errorf("manifest_loader: RouteEntry path %q has negative perf_budget_ms", e.Path)
	}
	return nil
}

// ---------------------------------------------------------------------------
// manifest YAML wrapper
// ---------------------------------------------------------------------------

// routeManifest is the top-level YAML structure.
type routeManifest struct {
	Routes []RouteEntry `yaml:"routes"`
}

// ---------------------------------------------------------------------------
// Load — parse the manifest file
// ---------------------------------------------------------------------------

// LoadManifest reads and parses the YAML manifest at path, returning all
// entries (including excluded ones).
//
// Validation rules:
//   - Unknown top-level YAML keys are rejected (strict mode).
//   - Every entry must have path, kind, and auth.
//   - Excluded entries must have an excluded_reason.
//   - Kind must be one of: page | api | action.
//   - Auth must be one of: required | public.
//
// Returns an error if the file is missing, malformed, or fails validation.
// Does NOT log route paths (clean output per NFR).
func LoadManifest(path string) ([]RouteEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest_loader: LoadManifest: read %s: %w", path, err)
	}

	// Use a strict decoder that rejects unknown fields.
	var manifest routeManifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if decErr := dec.Decode(&manifest); decErr != nil {
		return nil, fmt.Errorf("manifest_loader: LoadManifest: parse %s: %w (unknown YAML fields rejected)", path, decErr)
	}

	if len(manifest.Routes) == 0 {
		return nil, fmt.Errorf("manifest_loader: LoadManifest: %s contains no routes", path)
	}

	// Validate every entry.
	for i, entry := range manifest.Routes {
		if err := entry.Validate(); err != nil {
			return nil, fmt.Errorf("manifest_loader: LoadManifest: entry[%d]: %w", i, err)
		}
	}

	// Default method to GET if not set.
	for i := range manifest.Routes {
		if manifest.Routes[i].Method == "" {
			manifest.Routes[i].Method = "GET"
		}
		if manifest.Routes[i].PerfBudgetMs == 0 {
			manifest.Routes[i].PerfBudgetMs = 3000
		}
	}

	return manifest.Routes, nil
}

// ---------------------------------------------------------------------------
// Filter helpers
// ---------------------------------------------------------------------------

// FilterActive returns only entries that are NOT excluded.
func FilterActive(entries []RouteEntry) []RouteEntry {
	var out []RouteEntry
	for _, e := range entries {
		if !e.Excluded {
			out = append(out, e)
		}
	}
	return out
}

// FilterExcluded returns only entries that ARE excluded.
func FilterExcluded(entries []RouteEntry) []RouteEntry {
	var out []RouteEntry
	for _, e := range entries {
		if e.Excluded {
			out = append(out, e)
		}
	}
	return out
}

// FilterPublic returns only entries with auth=public.
func FilterPublic(entries []RouteEntry) []RouteEntry {
	var out []RouteEntry
	for _, e := range entries {
		if e.Auth == AuthPublic {
			out = append(out, e)
		}
	}
	return out
}

// FilterAuth returns only entries with auth=required.
func FilterAuth(entries []RouteEntry) []RouteEntry {
	var out []RouteEntry
	for _, e := range entries {
		if e.Auth == AuthRequired {
			out = append(out, e)
		}
	}
	return out
}

// FilterByKind returns only entries with the given kind.
func FilterByKind(entries []RouteEntry, kind RouteKind) []RouteEntry {
	var out []RouteEntry
	for _, e := range entries {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}
