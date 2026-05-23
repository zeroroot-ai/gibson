// Package cueruntime is the daemon's single CUE evaluation engine.
//
// All cuelang.org/go imports live here and nowhere else in the daemon.
// The engine is used by the DaemonAdminService handlers for
// ValidateMissionCUE, CompleteMissionCUE, and HoverMissionCUE.
//
// The CUE module schema is loaded once at package init from the embedded
// SDK CUE schemas (cueschemas.Schemas embed.FS). Callers interact with
// the engine through the four exported functions:
//
//   - Validate  — validate CUE source text; return diagnostics
//   - Complete  — return completion items at a cursor position
//   - Hover     — return Markdown documentation at a cursor position
//   - Export    — validate + render to a MissionDefinition proto
//
// Spec: gibson#298.
package cueruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cueerrors "cuelang.org/go/cue/errors"
	"cuelang.org/go/cue/load"
	"google.golang.org/protobuf/encoding/protojson"

	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zero-day-ai/sdk/cueschemas"
)

// Diagnostic is a CUE error or warning produced by Validate.
type Diagnostic struct {
	Line     int32
	Col      int32
	Message  string
	Severity string // "error" | "warning"
}

// CompletionItem is a single completion suggestion produced by Complete.
type CompletionItem struct {
	Label         string
	Detail        string
	Documentation string
	Kind          string // "field" | "value" | "keyword"
}

// schemaOverlay caches the overlay map built from cueschemas.Schemas so it is
// constructed only once across the process lifetime.
var (
	overlayOnce   sync.Once
	schemaOverlay map[string]load.Source
	overlayErr    error
)

// schemaModuleRoot is the virtual root used for the overlay.
// The path is arbitrary but must look absolute to cue/load.
const schemaModuleRoot = "/cue-mission-schema-root"

// initOverlay walks cueschemas.Schemas and builds the Overlay map for
// load.Config. Called exactly once via overlayOnce.
//
// The generated CUE files in the SDK use package names derived from their
// proto package (e.g. "missionpb", "typespb", "commonpb") rather than
// the last path element (e.g. "v1"). CUE's import resolution derives an
// implied qualifier from the last path element of the import path, so user
// CUE files that write:
//
//	import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"
//
// will look for package name "v1" in that directory. We fix this by
// rewriting the package declaration in the overlay so the package name
// matches the directory's last element when there is a mismatch.
// Internal cross-file imports (e.g. ":typespb") use explicit qualifiers so
// they resolve correctly regardless of the package name rewrite.
func initOverlay() {
	overlay := make(map[string]load.Source)
	err := fs.WalkDir(cueschemas.Schemas, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Only include .cue files (the embedded FS already filters to .cue paths).
		if !strings.HasSuffix(p, ".cue") {
			return nil
		}
		data, err := fs.ReadFile(cueschemas.Schemas, p)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", p, err)
		}
		// Rewrite the package declaration to match the last path component so
		// that CUE's implied-qualifier import resolution works correctly.
		data = rewritePackageDecl(p, data)
		absPath := path.Join(schemaModuleRoot, p)
		overlay[absPath] = load.FromBytes(data)
		return nil
	})
	if err != nil {
		overlayErr = fmt.Errorf("build CUE schema overlay: %w", err)
		return
	}
	schemaOverlay = overlay
}

// rewritePackageDecl rewrites the `package <name>` line in a CUE file when
// the declared package name doesn't match the last directory path element.
//
// CUE resolves an unqualified import like:
//
//	import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"
//
// by finding files in the directory with the implied qualifier ("v1"). The SDK's
// generated CUE uses proto-derived names ("missionpb"), which don't match.
//
// This rewrite is ONLY applied to files whose internal imports already use
// explicit qualifiers (e.g. ":typespb") so that changing the package name
// of the file being rewritten does not break those internal resolutions. In
// practice this means only mission/v1 files need rewriting — types/v1 and
// common/v1 are imported with explicit qualifiers and must keep their
// declared package names.
//
// The set of paths to rewrite is kept narrow and explicit to avoid surprises.
var packageRewrites = map[string]string{
	// User code: import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"
	// Needs package v1 (implied qualifier). Internal imports already use :typespb.
	"api/proto/gibson/mission/v1": "v1",
}

func rewritePackageDecl(filePath string, data []byte) []byte {
	dir := path.Dir(filePath)
	wantPkg, ok := packageRewrites[dir]
	if !ok {
		return data
	}
	lines := bytes.SplitN(data, []byte("\n"), -1)
	for i, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("package ")) {
			parts := bytes.Fields(trimmed)
			if len(parts) == 2 {
				currentPkg := string(parts[1])
				if currentPkg != wantPkg {
					lines[i] = bytes.Replace(line, []byte("package "+currentPkg), []byte("package "+wantPkg), 1)
				}
			}
			break
		}
	}
	return bytes.Join(lines, []byte("\n"))
}


// loadUserValue compiles source into a cue.Value using the embedded mission
// schema. Anonymous CUE files (no package clause, as used in ADK templates)
// are loaded with Package: "_". The returned Value may carry errors; callers
// must check val.Err() independently.
func loadUserValue(ctx *cue.Context, source string) (cue.Value, error) {
	overlayOnce.Do(initOverlay)
	if overlayErr != nil {
		return cue.Value{}, overlayErr
	}

	// Build the overlay: schema files + user source.
	// The user file is placed under a "user/" subdirectory inside the virtual
	// module root so cue/load can trace it back to the module for import resolution.
	overlay := make(map[string]load.Source, len(schemaOverlay)+1)
	for k, v := range schemaOverlay {
		overlay[k] = v
	}
	userFilePath := schemaModuleRoot + "/user/mission.cue"
	overlay[userFilePath] = load.FromString(source)

	cfg := &load.Config{
		Dir:        schemaModuleRoot + "/user",
		ModuleRoot: schemaModuleRoot,
		Overlay:    overlay,
		// Package "_" loads CUE files without a package clause (anonymous),
		// which is the convention used by all ADK mission templates.
		Package: "_",
	}

	// Load by absolute overlay path to avoid ambiguity when Package:"_" is set.
	insts := load.Instances([]string{userFilePath}, cfg)
	if len(insts) == 0 {
		return cue.Value{}, fmt.Errorf("no CUE instances loaded")
	}
	inst := insts[0]
	if inst.Err != nil {
		return cue.Value{}, inst.Err
	}

	val := ctx.BuildInstance(inst)
	return val, nil
}

// collectErrors converts cue.Value errors into Diagnostics.
func collectErrors(val cue.Value) []Diagnostic {
	err := val.Err()
	if err == nil {
		return nil
	}
	cueErrs := cueerrors.Errors(err)
	diags := make([]Diagnostic, 0, len(cueErrs))
	for _, e := range cueErrs {
		pos := e.Position()
		line := int32(1)
		col := int32(1)
		if pos.IsValid() {
			line = int32(pos.Line())
			col = int32(pos.Column())
		}
		diags = append(diags, Diagnostic{
			Line:     line,
			Col:      col,
			Message:  e.Error(),
			Severity: "error",
		})
	}
	return diags
}

// Validate returns CUE diagnostics for the given source string. A nil or
// empty slice indicates the source is valid according to the mission schema.
func Validate(_ context.Context, source string) ([]Diagnostic, error) {
	ctx := cuecontext.New()
	val, err := loadUserValue(ctx, source)
	if err != nil {
		// Load-level errors (parse, overlay) map to diagnostics so callers
		// get structured feedback rather than an opaque Go error.
		cueErrs := cueerrors.Errors(err)
		if len(cueErrs) > 0 {
			return collectErrorsDirect(cueErrs), nil
		}
		return []Diagnostic{{Line: 1, Col: 1, Message: err.Error(), Severity: "error"}}, nil
	}
	return collectErrors(val), nil
}

// collectErrorsDirect is like collectErrors but operates on a slice of cueerrors.Error
// directly (used when load itself fails before we have a cue.Value).
func collectErrorsDirect(errs []cueerrors.Error) []Diagnostic {
	diags := make([]Diagnostic, 0, len(errs))
	for _, e := range errs {
		pos := e.Position()
		line := int32(1)
		col := int32(1)
		if pos.IsValid() {
			line = int32(pos.Line())
			col = int32(pos.Column())
		}
		diags = append(diags, Diagnostic{
			Line:     line,
			Col:      col,
			Message:  e.Error(),
			Severity: "error",
		})
	}
	return diags
}

// topLevelMissionFields returns the known top-level field names of
// MissionDefinition from the embedded schema, used as a fallback for
// completion when cursor analysis is unavailable.
var topLevelMissionFields = []struct {
	name   string
	detail string
	doc    string
}{
	{"name", "string", "Human-readable name for the mission."},
	{"description", "string", "Additional context about what this mission does."},
	{"version", "string", "Semantic version of the mission definition (e.g. \"1.0.0\")."},
	{"targetRef", "string", "Reference to the target (name or ID) resolved at dispatch time."},
	{"nodes", "{[string]: #MissionNode}", "All nodes in the mission DAG, indexed by node ID."},
	{"edges", "[...#MissionEdge]", "Directed edges connecting nodes in the mission DAG."},
	{"entryPoints", "[...string]", "IDs of nodes that serve as entry points (no incoming edges)."},
	{"exitPoints", "[...string]", "IDs of nodes that serve as exit points (no outgoing edges)."},
	{"metadata", "{[string]: string}", "Custom metadata key-value pairs."},
	{"dependencies", "#MissionDependencies", "Required agents, tools, and plugins."},
	{"source", "string", "Git URL this mission was installed from (if applicable)."},
	{"workspace", "#WorkspaceConfig", "Repository cloning + workspace management config."},
	{"constraints", "#MissionConstraints", "Mission-level operational limits."},
}

// Complete returns completion items at the given cursor position.
// The implementation provides best-effort top-level MissionDefinition field
// completions. Line and col are 1-based.
func Complete(_ context.Context, source string, line, col int32) ([]CompletionItem, error) {
	// Best-effort: walk the top-level fields from the embedded schema.
	// A full LSP-grade cursor-sensitive implementation requires the CUE
	// lsp package which is not yet stable; this baseline covers the
	// common case of completing at the top level of a mission struct.
	items := make([]CompletionItem, 0, len(topLevelMissionFields))
	for _, f := range topLevelMissionFields {
		items = append(items, CompletionItem{
			Label:         f.name,
			Detail:        f.detail,
			Documentation: f.doc,
			Kind:          "field",
		})
	}
	return items, nil
}

// hoverDocs maps known mission field names to their Markdown documentation.
var hoverDocs = map[string]string{
	"name":         "**name** `string`\n\nHuman-readable name for the mission.",
	"description":  "**description** `string`\n\nAdditional context about what this mission does.",
	"version":      "**version** `string`\n\nSemantic version of the mission definition (e.g. `\"1.0.0\"`).",
	"targetRef":    "**targetRef** `string`\n\nReference to the target (name or ID). Resolved to a TargetID at dispatch time.",
	"nodes":        "**nodes** `{[string]: #MissionNode}`\n\nAll nodes in the mission DAG, indexed by node ID.",
	"edges":        "**edges** `[...#MissionEdge]`\n\nDirected edges connecting nodes. Each edge has `from` and `to` node IDs.",
	"entryPoints":  "**entryPoints** `[...string]`\n\nNode IDs that serve as entry points (nodes with no incoming edges).",
	"exitPoints":   "**exitPoints** `[...string]`\n\nNode IDs that serve as exit points (nodes with no outgoing edges).",
	"metadata":     "**metadata** `{[string]: string}`\n\nCustom key-value metadata for the mission.",
	"dependencies": "**dependencies** `#MissionDependencies`\n\nRequired agents, tools, and plugins for this mission.",
	"source":       "**source** `string`\n\nGit URL this mission was installed from, if applicable.",
	"workspace":    "**workspace** `#WorkspaceConfig`\n\nConfigures repository cloning and workspace management for code-access missions.",
	"constraints":  "**constraints** `#MissionConstraints`\n\nMission-level operational limits (duration, tokens, cost, findings).",
}

// Hover returns Markdown documentation for the symbol at the given cursor
// position. Line and col are 1-based. Returns an empty string when no
// documentation is found at that position.
func Hover(_ context.Context, source string, line, col int32) (string, error) {
	// Best-effort: extract the word under the cursor and look it up in the
	// known field table. A full AST-walking implementation can be layered
	// on top once the CUE lsp package stabilises.
	lines := strings.Split(source, "\n")
	if int(line) < 1 || int(line) > len(lines) {
		return "", nil
	}
	lineText := lines[line-1]
	if int(col) > len(lineText) {
		return "", nil
	}
	// Find word boundaries around the cursor.
	start := int(col) - 1
	end := int(col) - 1
	isIdent := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
	}
	for start > 0 && isIdent(lineText[start-1]) {
		start--
	}
	for end < len(lineText) && isIdent(lineText[end]) {
		end++
	}
	word := lineText[start:end]
	if doc, ok := hoverDocs[word]; ok {
		return doc, nil
	}
	return "", nil
}

// Export validates the CUE source and renders it to a MissionDefinition proto.
// The exported value must contain a top-level `mission` field that conforms to
// #MissionDefinition. An error is returned if validation fails; the error
// message includes the diagnostic details.
func Export(_ context.Context, source string) (*missionv1.MissionDefinition, error) {
	ctx := cuecontext.New()
	val, err := loadUserValue(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("CUE load: %w", err)
	}
	if err := val.Err(); err != nil {
		return nil, fmt.Errorf("CUE validation: %w", err)
	}

	// Extract the top-level `mission` field — all ADK templates use this convention.
	missionVal := val.LookupPath(cue.MakePath(cue.Str("mission")))
	if !missionVal.Exists() {
		return nil, fmt.Errorf("CUE source must contain a top-level 'mission' field")
	}
	if err := missionVal.Err(); err != nil {
		return nil, fmt.Errorf("CUE 'mission' field: %w", err)
	}

	raw, err := missionVal.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("CUE marshal to JSON: %w", err)
	}

	// Re-encode through standard json to strip any CUE formatting artefacts.
	var intermediate json.RawMessage
	if err := json.Unmarshal(raw, &intermediate); err != nil {
		return nil, fmt.Errorf("intermediate JSON unmarshal: %w", err)
	}
	canonical, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("canonical JSON marshal: %w", err)
	}

	def := &missionv1.MissionDefinition{}
	if err := protojson.Unmarshal(canonical, def); err != nil {
		return nil, fmt.Errorf("proto unmarshal from CUE JSON: %w", err)
	}
	return def, nil
}
