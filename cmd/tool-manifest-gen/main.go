// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command tool-manifest-gen writes one kind:tool catalog manifest per parser
// compiled into the gibson-executor image (ADR-0017).
//
// The input is executor-catalog.json: the verbatim `gibson-runner --list-tools`
// output of one digest-pinned executor image, plus the digest it came from.
// Capture it with `make tool-catalog-capture IMAGE=…@sha256:…`; regenerate the
// manifests with `make tool-manifests`. CI drift-gates the result, so a manifest
// can never disagree with the image it names.
//
// Hand-authoring these was the alternative, and it drifts silently: the first
// hand-written nmap manifest claimed 2Gi where the image asks for 512Mi, and
// nothing could have caught it.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// catalogEnvelope is executor-catalog.json: the image the catalog was captured
// from, and that image's tool list.
type catalogEnvelope struct {
	// Image is the digest-pinned executor image. Every generated manifest
	// names it, because one image carries every tool.
	Image string `json:"image"`
	Tools []tool `json:"tools"`
}

// tool is the subset of the executor's CatalogEntry a manifest needs. The
// executor owns the full shape; anything not read here is deliberately not part
// of the catalog contract.
type tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Resources   struct {
		VCPU   int32  `json:"vcpu"`
		Memory string `json:"memory"`
	} `json:"resources"`
}

func main() {
	if err := runCLI(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "tool-manifest-gen: %v\n", err)
		os.Exit(1)
	}
}

// runCLI is main's body, taking its arguments rather than reading the globals,
// so the flag wiring is exercised by tests instead of only by the Makefile.
func runCLI(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("tool-manifest-gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "internal/platform/componentcatalog/executor-catalog.json", "captured executor catalog")
	outDir := fs.String("out", "internal/platform/componentcatalog/manifests", "manifest output directory")
	captureImage := fs.String("capture-image", "", "with -capture-tools: record this digest-pinned image as the catalog source")
	captureTools := fs.String("capture-tools", "", "with -capture-image: raw `gibson-runner --list-tools` output to capture")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if (*captureImage == "") != (*captureTools == "") {
		return errors.New("-capture-image and -capture-tools must be given together")
	}
	if *captureImage != "" {
		if err := capture(*captureImage, *captureTools, *in); err != nil {
			return fmt.Errorf("capture: %w", err)
		}
	}
	return run(*in, *outDir)
}

// capture records a new executor catalog: the image it came from, plus that
// image's verbatim --list-tools output. Splitting capture from generation keeps
// the generator hermetic — regenerating manifests never needs docker, a network,
// or registry credentials, so CI can drift-gate it on any runner.
func capture(image, toolsPath, out string) error {
	// #nosec G304 -- a build-time generator reading the path its own operator
	// passed on the command line. There is no untrusted input here.
	raw, err := os.ReadFile(toolsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", toolsPath, err)
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		return fmt.Errorf("parse --list-tools output: %w", err)
	}
	// Round-trip through the envelope's own validation before writing, so a bad
	// capture fails here rather than leaving a broken JSON for the next reader.
	env := struct {
		Image string            `json:"image"`
		Tools []json.RawMessage `json:"tools"`
	}{Image: image, Tools: tools}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	body = append(body, '\n')
	var check catalogEnvelope
	if err := json.Unmarshal(body, &check); err != nil {
		return fmt.Errorf("captured envelope does not decode: %w", err)
	}
	if err := validate(check); err != nil {
		return err
	}
	if err := os.WriteFile(out, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("captured %d tools from %s\n", len(check.Tools), image)
	return nil
}

func run(in, outDir string) error {
	// #nosec G304 -- build-time generator, path from its own flags.
	raw, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", in, err)
	}
	// Unknown fields are expected, not an error: the executor's CatalogEntry
	// carries more than a manifest needs (input schema, parse quality, tags),
	// and it owns that shape. Only the fields read below are contract. A
	// mistyped envelope key still fails loudly — it leaves Image empty, which
	// validate rejects.
	var env catalogEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode %s: %w", in, err)
	}
	if err := validate(env); err != nil {
		return err
	}

	// Deterministic output: same input, same bytes, so the drift gate compares
	// content and never ordering.
	sort.Slice(env.Tools, func(i, j int) bool { return env.Tools[i].Name < env.Tools[j].Name })

	// Every manifest this generator owns is rewritten from scratch. A tool
	// dropped from the image must lose its manifest too, or the catalog would
	// keep offering a tool the image can no longer run.
	owned, err := filepath.Glob(filepath.Join(outDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("scan %s: %w", outDir, err)
	}
	stale := map[string]bool{}
	for _, p := range owned {
		if isGenerated(p) {
			stale[p] = true
		}
	}

	for _, t := range env.Tools {
		path := filepath.Join(outDir, t.Name+".yaml")
		if err := os.WriteFile(path, manifest(env.Image, t), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		delete(stale, path)
	}
	for p := range stale {
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("remove stale %s: %w", p, err)
		}
		fmt.Fprintf(os.Stderr, "removed stale manifest %s (its tool is no longer in the image)\n", p)
	}
	fmt.Printf("wrote %d tool manifests from %s\n", len(env.Tools), env.Image)
	return nil
}

func validate(env catalogEnvelope) error {
	if !strings.Contains(env.Image, "@sha256:") {
		return fmt.Errorf("image %q must be digest-pinned (…@sha256:…): a tag would make "+
			"\"which tools does this cluster have\" unanswerable", env.Image)
	}
	if len(env.Tools) == 0 {
		return errors.New("catalog lists no tools; refusing to delete every manifest")
	}
	seen := map[string]bool{}
	for _, t := range env.Tools {
		switch {
		case t.Name == "":
			return errors.New("a tool has no name")
		case seen[t.Name]:
			return fmt.Errorf("tool %q listed twice", t.Name)
		case t.Description == "":
			return fmt.Errorf("tool %q has no description", t.Name)
		case t.Resources.VCPU <= 0:
			return fmt.Errorf("tool %q declares vcpu %d", t.Name, t.Resources.VCPU)
		case t.Resources.Memory == "":
			return fmt.Errorf("tool %q declares no memory", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

// generatedHeader marks a manifest this generator owns. It is also how the
// generator recognises which files it may delete — a hand-authored manifest of
// another kind sitting in the same directory is never touched.
const generatedHeader = "# Code generated by cmd/tool-manifest-gen. DO NOT EDIT."

func isGenerated(path string) bool {
	// #nosec G304 -- path came from this generator's own output-directory glob.
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(b), generatedHeader)
}

func manifest(image string, t tool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", generatedHeader)
	fmt.Fprintf(&b, "# Source: `gibson-runner --list-tools` from the image below.\n")
	fmt.Fprintf(&b, "# Regenerate with `make tool-manifests`; capture a new image with\n")
	fmt.Fprintf(&b, "# `make tool-catalog-capture IMAGE=…@sha256:…`.\n")
	fmt.Fprintf(&b, "id: %s\n", t.Name)
	fmt.Fprintf(&b, "kind: tool\n")
	// displayName is the tool's own name, not a prettified variant. These are
	// proper command names (nmap, httpx, dnsx); inventing "Httpx" here would be
	// presentation invented by a generator, and wrong besides.
	fmt.Fprintf(&b, "displayName: %s\n", t.Name)
	fmt.Fprintf(&b, "description: >-\n")
	for _, line := range wrap(t.Description, 74) {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	fmt.Fprintf(&b, "# A scanner reaches the mission's targets. The effective egress of a tool\n")
	fmt.Fprintf(&b, "# launch is bounded by the dispatching agent's ceiling (ADR-0016), so this\n")
	fmt.Fprintf(&b, "# is a ceiling, not a grant.\n")
	fmt.Fprintf(&b, "egressAllow:\n  - \"*\"\n")
	fmt.Fprintf(&b, "spec:\n")
	// Third-party scanners parsing attacker-influenced output: untrusted, and
	// therefore always sandboxed (ADR-0010).
	fmt.Fprintf(&b, "  contentTrust: untrusted\n")
	fmt.Fprintf(&b, "  dispatchMode: sandboxed\n")
	fmt.Fprintf(&b, "  image: %s\n", image)
	fmt.Fprintf(&b, "  command: gibson-runner\n")
	fmt.Fprintf(&b, "  resources:\n")
	fmt.Fprintf(&b, "    vcpu: %d\n", t.Resources.VCPU)
	fmt.Fprintf(&b, "    memory: %s\n", t.Resources.Memory)
	return []byte(b.String())
}

// wrap breaks a description onto lines that fit the YAML block scalar without
// changing its words.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	lines := []string{}
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(lines, cur)
}
