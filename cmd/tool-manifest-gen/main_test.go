// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The generator's job is to make a manifest that cannot disagree with the image
// it names. These cover the ways that guarantee could break: a tag instead of a
// digest, a tool that left the image, a hand-authored manifest caught in the
// blast radius, and non-deterministic output that would make the drift gate
// flap.

func envelope(t *testing.T, image string, tools ...tool) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"image": image, "tools": tools})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	return path
}

func mkTool(name, desc string, vcpu int32, mem string) tool {
	var tl tool
	tl.Name = name
	tl.Description = desc
	tl.Resources.VCPU = vcpu
	tl.Resources.Memory = mem
	return tl
}

const digestImage = "ghcr.io/zeroroot-ai/gibson-executor@sha256:c2d7b916f610c3e3d6ec285cdaf9db95437e26cf111c152df71a27438ade2c16"

// TestRun_WritesManifestPerTool: one tool in, one manifest out, carrying the
// image digest, the launch command, and the image's own resource hint.
func TestRun_WritesManifestPerTool(t *testing.T) {
	in := envelope(t, digestImage, mkTool("nmap", "Port scanner.", 2, "512Mi"))
	out := t.TempDir()
	if err := run(in, out); err != nil {
		t.Fatalf("run: %v", err)
	}
	// #nosec G304 -- t.TempDir() path
	body, err := os.ReadFile(filepath.Join(out, "nmap.yaml"))
	if err != nil {
		t.Fatalf("read generated manifest: %v", err)
	}
	got := string(body)
	for _, want := range []string{
		generatedHeader,
		"id: nmap",
		"kind: tool",
		"contentTrust: untrusted",
		"dispatchMode: sandboxed",
		"image: " + digestImage,
		"command: gibson-runner",
		"vcpu: 2",
		"memory: 512Mi",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated manifest is missing %q:\n%s", want, got)
		}
	}
}

// TestRun_TaggedImageRefused: a tag makes "which tools does this cluster have"
// unanswerable, so a non-digest image is refused rather than generated from.
func TestRun_TaggedImageRefused(t *testing.T) {
	in := envelope(t, "ghcr.io/zeroroot-ai/gibson-executor:latest", mkTool("nmap", "Port scanner.", 2, "512Mi"))
	err := run(in, t.TempDir())
	if err == nil {
		t.Fatal("a tagged image must be refused")
	}
	if !strings.Contains(err.Error(), "digest-pinned") {
		t.Errorf("error should name the digest requirement, got: %v", err)
	}
}

// TestRun_EmptyCatalogRefused: an empty tool list would delete every manifest.
// That is indistinguishable from a broken capture, so it fails loud instead.
func TestRun_EmptyCatalogRefused(t *testing.T) {
	if err := run(envelope(t, digestImage), t.TempDir()); err == nil {
		t.Fatal("an empty catalog must be refused, not allowed to empty the directory")
	}
}

// TestRun_IncompleteToolRefused: a tool missing the fields a launch needs is a
// broken capture. Generating a manifest with vcpu 0 would fail at dispatch, far
// from the cause.
func TestRun_IncompleteToolRefused(t *testing.T) {
	for name, tl := range map[string]tool{
		"no name":        mkTool("", "Scanner.", 2, "512Mi"),
		"no description": mkTool("nmap", "", 2, "512Mi"),
		"no vcpu":        mkTool("nmap", "Scanner.", 0, "512Mi"),
		"no memory":      mkTool("nmap", "Scanner.", 2, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(envelope(t, digestImage, tl), t.TempDir()); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// TestRun_RemovesManifestOfDepartedTool: a tool dropped from the image loses its
// manifest, or the catalog keeps offering a tool the image can no longer run.
func TestRun_RemovesManifestOfDepartedTool(t *testing.T) {
	out := t.TempDir()
	both := envelope(t, digestImage,
		mkTool("nmap", "Port scanner.", 2, "512Mi"),
		mkTool("retired", "Removed next release.", 1, "256Mi"))
	if err := run(both, out); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "retired.yaml")); err != nil {
		t.Fatalf("setup: retired.yaml should exist after the first run: %v", err)
	}

	only := envelope(t, digestImage, mkTool("nmap", "Port scanner.", 2, "512Mi"))
	if err := run(only, out); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "retired.yaml")); !os.IsNotExist(err) {
		t.Error("a tool no longer in the image must lose its manifest")
	}
	if _, err := os.Stat(filepath.Join(out, "nmap.yaml")); err != nil {
		t.Errorf("the surviving tool keeps its manifest: %v", err)
	}
}

// TestRun_LeavesHandAuthoredManifestsAlone: agents, plugins and connectors are
// hand-authored and live in the same directory. The generator owns only files
// carrying its header, so a sweep never deletes someone else's manifest.
func TestRun_LeavesHandAuthoredManifestsAlone(t *testing.T) {
	out := t.TempDir()
	handAuthored := filepath.Join(out, "zerocool.yaml")
	const body = "id: zerocool\nkind: agent\n"
	if err := os.WriteFile(handAuthored, []byte(body), 0o600); err != nil {
		t.Fatalf("write hand-authored manifest: %v", err)
	}

	if err := run(envelope(t, digestImage, mkTool("nmap", "Port scanner.", 2, "512Mi")), out); err != nil {
		t.Fatalf("run: %v", err)
	}

	// #nosec G304 -- t.TempDir() path
	got, err := os.ReadFile(handAuthored)
	if err != nil {
		t.Fatalf("the hand-authored manifest was deleted: %v", err)
	}
	if string(got) != body {
		t.Errorf("the hand-authored manifest was rewritten:\n%s", got)
	}
}

// TestRun_Deterministic: same input, same bytes. The drift gate compares
// content, so unstable output would fail CI on an unrelated change.
func TestRun_Deterministic(t *testing.T) {
	in := envelope(t, digestImage,
		mkTool("nuclei", "Template scanner.", 2, "1Gi"),
		mkTool("dnsx", "DNS resolver.", 1, "256Mi"),
		mkTool("nmap", "Port scanner.", 2, "512Mi"))

	first, second := t.TempDir(), t.TempDir()
	if err := run(in, first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := run(in, second); err != nil {
		t.Fatalf("second run: %v", err)
	}
	for _, name := range []string{"nmap.yaml", "nuclei.yaml", "dnsx.yaml"} {
		// #nosec G304 -- t.TempDir() path
		a, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// #nosec G304 -- t.TempDir() path
		b, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between runs; the drift gate would flap", name)
		}
	}
}

// TestCapture_RejectsTaggedImage: the digest rule is enforced at capture too,
// so a bad envelope is never written in the first place.
func TestCapture_RejectsTaggedImage(t *testing.T) {
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(tools, []byte(`[{"name":"nmap","description":"d","resources":{"vcpu":2,"memory":"512Mi"}}]`), 0o600); err != nil {
		t.Fatalf("write tools: %v", err)
	}
	out := filepath.Join(dir, "catalog.json")
	if err := capture("ghcr.io/zeroroot-ai/gibson-executor:v1", tools, out); err == nil {
		t.Fatal("capture must refuse a tagged image")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("a refused capture must not write the envelope")
	}
}

// TestCapture_WritesGeneratableEnvelope: what capture writes is exactly what the
// generator reads — the two halves cannot drift apart.
func TestCapture_WritesGeneratableEnvelope(t *testing.T) {
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools.json")
	// Extra fields mirror the executor's real CatalogEntry: the generator reads
	// a subset and must not choke on the rest.
	raw := `[{"name":"nmap","description":"Port scanner.","tags":["recon"],
	          "input_schema":{"type":"object"},"default_timeout_seconds":300,
	          "resources":{"vcpu":2,"memory":"512Mi"}}]`
	if err := os.WriteFile(tools, []byte(raw), 0o600); err != nil {
		t.Fatalf("write tools: %v", err)
	}
	out := filepath.Join(dir, "catalog.json")
	if err := capture(digestImage, tools, out); err != nil {
		t.Fatalf("capture: %v", err)
	}

	manifests := t.TempDir()
	if err := run(out, manifests); err != nil {
		t.Fatalf("generate from captured envelope: %v", err)
	}
	if _, err := os.Stat(filepath.Join(manifests, "nmap.yaml")); err != nil {
		t.Errorf("captured envelope did not generate a manifest: %v", err)
	}
}

// The CLI surface. main() is a three-line shell over runCLI, so the flag wiring
// and the capture→generate sequencing are covered here rather than only by
// whatever the Makefile happens to pass.

// TestRunCLI_GeneratesFromCapturedCatalog: the default path — read the
// committed envelope, write manifests.
func TestRunCLI_GeneratesFromCapturedCatalog(t *testing.T) {
	in := envelope(t, digestImage, mkTool("nmap", "Port scanner.", 2, "512Mi"))
	out := t.TempDir()
	if err := runCLI([]string{"-in", in, "-out", out}, io.Discard); err != nil {
		t.Fatalf("runCLI: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "nmap.yaml")); err != nil {
		t.Errorf("no manifest written: %v", err)
	}
}

// TestRunCLI_CaptureThenGenerate: -capture-image with -capture-tools records a
// new envelope and regenerates in one pass, which is what
// `make tool-catalog-capture` relies on.
func TestRunCLI_CaptureThenGenerate(t *testing.T) {
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(tools, []byte(
		`[{"name":"naabu","description":"Port scanner.","resources":{"vcpu":2,"memory":"512Mi"}}]`), 0o600); err != nil {
		t.Fatalf("write tools: %v", err)
	}
	catalog := filepath.Join(dir, "catalog.json")
	out := t.TempDir()

	if err := runCLI([]string{
		"-capture-image", digestImage, "-capture-tools", tools,
		"-in", catalog, "-out", out,
	}, io.Discard); err != nil {
		t.Fatalf("runCLI capture: %v", err)
	}
	if _, err := os.Stat(catalog); err != nil {
		t.Errorf("capture wrote no envelope: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "naabu.yaml")); err != nil {
		t.Errorf("capture did not regenerate manifests: %v", err)
	}
}

// TestRunCLI_HalfACaptureIsRefused: capturing needs both the image and its tool
// list. One without the other would either record an image whose tools were
// never read, or a tool list attributed to no image.
func TestRunCLI_HalfACaptureIsRefused(t *testing.T) {
	for name, args := range map[string][]string{
		"image without tools": {"-capture-image", digestImage},
		"tools without image": {"-capture-tools", "/nonexistent"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runCLI(args, io.Discard); err == nil {
				t.Fatal("half a capture must be refused")
			}
		})
	}
}

// TestRunCLI_ReportsUnreadableInput: a missing catalog names the file, rather
// than surfacing as an empty catalog or a nil-pointer panic.
func TestRunCLI_ReportsUnreadableInput(t *testing.T) {
	err := runCLI([]string{"-in", filepath.Join(t.TempDir(), "absent.json"), "-out", t.TempDir()}, io.Discard)
	if err == nil {
		t.Fatal("a missing catalog must be an error")
	}
	if !strings.Contains(err.Error(), "absent.json") {
		t.Errorf("the error should name the missing file, got: %v", err)
	}
}

// TestRunCLI_RejectsUnknownFlag: a typo'd flag must stop the run, not silently
// regenerate with defaults over the real manifest directory.
func TestRunCLI_RejectsUnknownFlag(t *testing.T) {
	if err := runCLI([]string{"-not-a-flag"}, io.Discard); err == nil {
		t.Fatal("an unknown flag must be refused")
	}
}

// TestRun_MalformedCatalogRefused: truncated or non-JSON input is a broken
// capture, and says so.
func TestRun_MalformedCatalogRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := run(path, t.TempDir()); err == nil {
		t.Fatal("malformed JSON must be refused")
	}
}

// TestCapture_ReportsUnreadableToolList: the docker step in
// `make tool-catalog-capture` can fail and leave nothing behind; the generator
// must name that rather than write an empty catalog.
func TestCapture_ReportsUnreadableToolList(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.json")
	if err := capture(digestImage, filepath.Join(t.TempDir(), "missing.json"), out); err == nil {
		t.Fatal("an unreadable tool list must be refused")
	}
}

// TestCapture_ReportsMalformedToolList: --list-tools output that is not a JSON
// array is a broken capture, not an empty one.
func TestCapture_ReportsMalformedToolList(t *testing.T) {
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(tools, []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := capture(digestImage, tools, filepath.Join(dir, "catalog.json")); err == nil {
		t.Fatal("malformed --list-tools output must be refused")
	}
}

// TestCapture_EmptyToolListRefused: an image that reports no tools would delete
// every manifest on the next generate.
func TestCapture_EmptyToolListRefused(t *testing.T) {
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(tools, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := capture(digestImage, tools, filepath.Join(dir, "catalog.json")); err == nil {
		t.Fatal("an empty tool list must be refused at capture")
	}
}

// TestWrap_KeepsEveryWord: the description is reflowed for the YAML block
// scalar, never edited.
func TestWrap_KeepsEveryWord(t *testing.T) {
	const desc = "Template-based vulnerability scanner (ProjectDiscovery nuclei). " +
		"Emits typed Finding nodes with severity and template metadata."
	lines := wrap(desc, 40)
	if len(lines) < 2 {
		t.Fatalf("a long description must wrap, got %d line(s)", len(lines))
	}
	if strings.Join(lines, " ") != desc {
		t.Errorf("wrapping changed the text:\n got %q\nwant %q", strings.Join(lines, " "), desc)
	}
	for _, l := range lines {
		if strings.HasPrefix(l, " ") || strings.HasSuffix(l, " ") {
			t.Errorf("line %q carries padding that would land in the YAML", l)
		}
	}
	if wrap("", 40) != nil {
		t.Error("an empty description wraps to nothing, not to one empty line")
	}
}
