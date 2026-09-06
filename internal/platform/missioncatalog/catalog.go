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

// Params are the values a checked-in mission is rendered with. Every field is
// required: CUE refuses an incomplete render rather than substituting an empty
// string, so a missing commit fails loudly instead of scanning HEAD, and a
// missing image fails instead of scanning nothing.
//
// The runtime target is deliberately absent. It is bound from the mission's
// target at submit, never from a parameter, so a caller cannot point a scan at
// a host the tenant has not registered.
type Params struct {
	// Application is the Application key every observation of this scan hangs
	// off, and the thing the findings are counted against.
	Application string
	// RepositoryURL is the git remote the source branch clones.
	RepositoryURL string
	// Ref is the branch the pipeline built.
	Ref string
	// Commit is the exact commit the pipeline built.
	Commit string
	// PipelineID identifies the pipeline that triggered this scan.
	PipelineID string
	// PipelineURL is that pipeline, for a human following the trail.
	PipelineURL string
	// ImageRef is the image the pipeline published, by digest.
	ImageRef string
}

// paramField binds one wire name to the field it lands in. The pointer is what
// lets a single declaration serve reading and writing both.
type paramField struct {
	name  string
	value *string
}

// fields is the ONE declaration of this mission's parameter names and where
// each one lands. Validation, rendering, and decoding a caller's map all read
// it, so a parameter added to the struct cannot be wired into one of the three
// and silently forgotten in the others — which would surface as a caller
// sending a value that renders as empty, or as a key refused for being
// unknown when it is not.
func (p *Params) fields() []paramField {
	return []paramField{
		{"application", &p.Application},
		{"repositoryUrl", &p.RepositoryURL},
		{"ref", &p.Ref},
		{"commit", &p.Commit},
		{"pipelineId", &p.PipelineID},
		{"pipelineUrl", &p.PipelineURL},
		{"imageRef", &p.ImageRef},
	}
}

// ParamNames lists the parameters a checked-in mission takes, in declaration
// order, so a caller or an error message can name them without duplicating the
// list.
func ParamNames() []string {
	var p Params
	declared := p.fields()
	out := make([]string, 0, len(declared))
	for _, f := range declared {
		out = append(out, f.name)
	}
	return out
}

// ParamsFromMap decodes a caller-supplied parameter map.
//
// An UNKNOWN key is refused, never ignored. That refusal is the whole of the
// smuggling defence: Params has no target or host field, so a caller sending
// `host: evil.example.com` into a map that quietly drops unrecognised keys
// would receive no error and reasonably believe it bound. The runtime target
// comes from the mission's target at submit and from nowhere else.
//
// Unknown keys are reported together, and sorted, so a caller with several
// typos sees them in one answer rather than one per attempt.
func ParamsFromMap(in map[string]string) (Params, error) {
	var p Params
	known := make(map[string]*string, len(p.fields()))
	for _, f := range p.fields() {
		known[f.name] = f.value
	}
	var unknown []string
	for k, v := range in {
		dst, ok := known[k]
		if !ok {
			unknown = append(unknown, k)
			continue
		}
		*dst = v
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Params{}, fmt.Errorf(
			"missioncatalog: unknown parameter %s (known: %s)",
			strings.Join(unknown, ", "), strings.Join(ParamNames(), ", "))
	}
	return p, nil
}

// missing returns the names of the parameters left empty, in declaration
// order. Reporting all of them at once matters: a caller wiring this up for
// the first time should see every field it forgot in one error, not discover
// them one render at a time.
func (p Params) missing() []string {
	var out []string
	for _, f := range p.fields() {
		if strings.TrimSpace(*f.value) == "" {
			out = append(out, f.name)
		}
	}
	return out
}

// cueBlock renders the parameters as a CUE fragment that unifies with the
// definition's `_params`. Values are quoted with %q so a value carrying a
// quote or a backslash cannot terminate the string and inject CUE.
func (p Params) cueBlock() string {
	var b strings.Builder
	b.WriteString("\n_params: {\n")
	for _, f := range p.fields() {
		fmt.Fprintf(&b, "\t%s: %q\n", f.name, *f.value)
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
func Render(ctx context.Context, name string, p Params) (*missionv1.MissionDefinition, error) {
	if missing := p.missing(); len(missing) > 0 {
		return nil, fmt.Errorf("missioncatalog: mission %q needs %s", name, strings.Join(missing, ", "))
	}
	src, err := Source(name)
	if err != nil {
		return nil, err
	}
	def, err := cueruntime.Export(ctx, src+p.cueBlock())
	if err != nil {
		return nil, fmt.Errorf("missioncatalog: render %q: %w", name, err)
	}
	return def, nil
}
