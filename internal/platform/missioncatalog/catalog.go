// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package missioncatalog holds the first-party mission definitions gibson
// ships, compiled into the signed binary.
//
// It is deliberately NOT the component catalog (ADR-0018). A component is the
// thing a mission dispatches — it has an image, an egress ceiling, and a
// per-tenant `can_execute` gate. A Mission is the work-graph that does the
// dispatching: no image, no egress of its own, never dispatched. Modelling one
// as the other would put a mission and the tools it calls behind the same FGA
// tuple, so revoking a tool would read as revoking the mission that uses it.
//
// Authorization is unchanged by anything here. A mission is not gated; every
// node it dispatches is, exactly as it would be if a person had authored the
// same graph by hand.
package missioncatalog

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
)

// missionFS holds the first-party mission definitions. One file is one
// mission, named for the mission it defines.
//
//go:embed missions/*.cue
var missionFS embed.FS

// Parameters are declared by each mission, in its own CUE, and nowhere else.
//
// They used to be a flat Go struct shared by every mission in the catalog, with
// Render requiring all seven fields for any mission name. That made a second
// mission impossible unless its caller invented a pipeline id and an image
// digest for work that has neither (gibson#499). It also carried the names three
// times — struct, validation, decode — which is the drift the old fields()
// comment was written to manage.
//
// So the closed set is read from the mission. The refusal of an UNKNOWN key is
// unchanged in kind and is the whole smuggling defence: no mission declares a
// target or a host, so a caller sending `host: evil.example.com` into a map that
// quietly dropped unrecognised keys would receive no error and reasonably
// believe it bound. The runtime target comes from the mission's target at submit
// and from nowhere else.

// checkParams refuses a caller's map against what the mission declares.
//
// Unknown keys and missing keys are each reported together, and sorted, so a
// caller with several typos or several omissions sees them in one answer rather
// than one per attempt.
func checkParams(mission string, declared []string, in map[string]string) error {
	known := make(map[string]bool, len(declared))
	for _, n := range declared {
		known[n] = true
	}

	var unknown []string
	for k := range in {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("missioncatalog: mission %q has no parameter %s (it takes %s)",
			mission, strings.Join(unknown, ", "), namesOrNone(declared))
	}

	var missing []string
	for _, n := range declared {
		if strings.TrimSpace(in[n]) == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missioncatalog: mission %q needs %s", mission, strings.Join(missing, ", "))
	}
	return nil
}

func namesOrNone(declared []string) string {
	if len(declared) == 0 {
		return "no parameters"
	}
	return strings.Join(declared, ", ")
}

// cueBlock renders the parameters as a CUE fragment that unifies with the
// mission's `_params`. Values are quoted with %q so a value carrying a quote or
// a backslash cannot terminate the string and inject CUE. Keys are emitted in
// the declared (sorted) order, so the same inputs render the same bytes.
func cueBlock(declared []string, in map[string]string) string {
	if len(declared) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n_params: {\n")
	for _, n := range declared {
		fmt.Fprintf(&b, "\t%s: %q\n", n, in[n])
	}
	b.WriteString("}\n")
	return b.String()
}

// Names lists the checked-in missions, sorted, so a caller can enumerate what
// gibson ships without reaching into the embedded filesystem.
func Names() []string {
	entries, err := fs.ReadDir(missionFS, "missions")
	if err != nil {
		// Unreachable: the directory is embedded at compile time.
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".cue"))
	}
	sort.Strings(names)
	return names
}

// Source returns the raw CUE for a checked-in mission, so a person can read or
// copy what the daemon will run rather than trusting a rendered summary.
func Source(name string) (string, error) {
	if strings.ContainsAny(name, "/\\.") {
		return "", fmt.Errorf("missioncatalog: %q is not a mission name", name)
	}
	data, err := missionFS.ReadFile("missions/" + name + ".cue")
	if err != nil {
		return "", fmt.Errorf("missioncatalog: no checked-in mission %q (have %s)", name, strings.Join(Names(), ", "))
	}
	return string(data), nil
}

// Render returns the mission definition for a checked-in mission with its
// parameters applied. The definition is authoritative: this is the single
// place the graph is described, and the always-on agent references it rather
// than rebuilding it (ADR-0018).
//
// params is validated against what this mission declares, so an unknown key is
// refused rather than dropped and a missing one is refused rather than rendered
// as an empty string into a scan target.
func Render(ctx context.Context, name string, params map[string]string) (*missionv1.MissionDefinition, error) {
	src, err := Source(name)
	if err != nil {
		return nil, err
	}
	declared, err := cueruntime.DeclaredParams(src)
	if err != nil {
		return nil, fmt.Errorf("missioncatalog: read the parameters of %q: %w", name, err)
	}
	if err := checkParams(name, declared, params); err != nil {
		return nil, err
	}
	def, err := cueruntime.Export(ctx, src+cueBlock(declared, params))
	if err != nil {
		return nil, fmt.Errorf("missioncatalog: render %q: %w", name, err)
	}
	return def, nil
}

// Entry is one checked-in mission as a caller needs to see it before running
// it: what it is, and what it requires.
type Entry struct {
	Name        string
	Description string
	Version     string
	// DeclaredParams is the closed set, sorted. Render refuses a key that is
	// not here and refuses a render that omits one, so a caller builds its
	// request from this list.
	DeclaredParams []string
}

// Describe reads one mission's identity and its parameter set.
//
// Without rendering. A listing has no parameter values to render with, and
// rendering each mission against placeholder values just to read its
// description would be three failure modes and a set of fake values in
// exchange for three string literals.
func Describe(name string) (Entry, error) {
	src, err := Source(name)
	if err != nil {
		return Entry{}, err
	}
	meta, err := cueruntime.Meta(src)
	if err != nil {
		return Entry{}, fmt.Errorf("missioncatalog: read the identity of %q: %w", name, err)
	}
	declared, err := cueruntime.DeclaredParams(src)
	if err != nil {
		return Entry{}, fmt.Errorf("missioncatalog: read the parameters of %q: %w", name, err)
	}
	sort.Strings(declared)

	// The catalog NAME is authoritative, not the name inside the CUE. They
	// agree today and a test says so; if they ever disagree, the name a caller
	// passes to Render is the one that must come back.
	return Entry{
		Name:           name,
		Description:    meta.Description,
		Version:        meta.Version,
		DeclaredParams: declared,
	}, nil
}

// Entries describes every checked-in mission, sorted by name.
//
// A mission that cannot be described fails the whole listing rather than being
// skipped: silently missing from the list is how a person concludes the
// platform does not ship it.
func Entries() ([]Entry, error) {
	names := Names()
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		e, err := Describe(name)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
