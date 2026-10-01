// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/targetbind"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// updateGolden rewrites the recorded render instead of comparing against it.
var updateGolden = flag.Bool("update", false, "rewrite testdata/scan-rendered.json from the current render")

// validParams is a complete parameter set for the checked-in scan mission,
// keyed by the names scan.cue itself declares.
func validParams() map[string]string {
	return map[string]string{
		"application":   "customer-portal",
		"repositoryUrl": "https://gitlab.com/examplebank/customer-portal.git",
		"ref":           "main",
		"commit":        "0123456789abcdef0123456789abcdef01234567",
		"pipelineId":    "8891",
		"pipelineUrl":   "https://gitlab.com/examplebank/customer-portal/-/pipelines/8891",
		"imageRef":      "registry.gitlab.com/examplebank/customer-portal@sha256:abc",
	}
}

// TestValidParams_CoversEveryDeclaredParameter keeps the literal above honest.
// A parameter added to scan.cue and not here would make every other test in this
// file fail on a missing value, which is a confusing way to learn it; this says
// it directly.
func TestValidParams_CoversEveryDeclaredParameter(t *testing.T) {
	names, err := ParamNames("scan")
	if err != nil {
		t.Fatal(err)
	}
	got := validParams()
	if len(got) != len(names) {
		t.Fatalf("validParams has %d entries, scan declares %d: %v vs %v", len(got), len(names), got, names)
	}
	for _, n := range names {
		if _, ok := got[n]; !ok {
			t.Errorf("validParams does not set the declared parameter %q", n)
		}
	}
}

func TestNames_ListsTheCheckedInMissions(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no checked-in missions; the embed produced nothing")
	}
	var found bool
	for _, n := range names {
		if n == "scan" {
			found = true
		}
		if strings.HasSuffix(n, ".cue") {
			t.Errorf("name %q kept its extension; callers name a mission, not a file", n)
		}
	}
	if !found {
		t.Errorf("scan is not in %v", names)
	}
}

func TestSource_RefusesAPathInsteadOfAName(t *testing.T) {
	// A name reaching the embedded filesystem as a path is how a caller walks
	// out of the mission directory. Names are names.
	for _, bad := range []string{"../catalog", "missions/scan", "scan.cue", "a\\b"} {
		if _, err := Source(bad); err == nil {
			t.Errorf("Source(%q) was accepted; it is not a mission name", bad)
		}
	}
}

func TestSource_UnknownMissionNamesWhatExists(t *testing.T) {
	_, err := Source("nope")
	if err == nil {
		t.Fatal("an unknown mission rendered")
	}
	// The error has to be actionable: a caller that guessed wrong should see
	// the real names rather than go reading the source tree.
	if !strings.Contains(err.Error(), "scan") {
		t.Errorf("error does not name what exists: %v", err)
	}
}

func TestRender_MissingParametersAreAllReportedAtOnce(t *testing.T) {
	_, err := Render(context.Background(), "scan", map[string]string{"application": "customer-portal"})
	if err == nil {
		t.Fatal("an incomplete render was accepted; an empty commit would scan HEAD")
	}
	for _, want := range []string{"commit", "imageRef", "repositoryUrl", "ref", "pipelineId", "pipelineUrl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q, so a caller fixes one field per render: %v", want, err)
		}
	}
}

func TestRender_WhitespaceIsNotAValue(t *testing.T) {
	p := validParams()
	p["commit"] = "   "
	_, err := Render(context.Background(), "scan", p)
	if err == nil || !strings.Contains(err.Error(), "commit") {
		t.Fatalf("a blank commit was accepted as a value: %v", err)
	}
}

func TestRender_ScanFansOutAcrossImageSourceAndRuntime(t *testing.T) {
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if def.GetName() != "scan" {
		t.Errorf("name = %q, want scan", def.GetName())
	}

	// The three views of one Application. Losing any one of them silently
	// narrows what the scan can see, which is exactly the failure that looks
	// like a clean application.
	wantTools := map[string]string{
		"image":    "trivy",
		"ports":    "naabu",
		"services": "httpx",
		"web":      "nuclei",
		"tls":      "tlsx",
	}
	nodes := def.GetNodes()
	for id, tool := range wantTools {
		n, ok := nodes[id]
		if !ok {
			t.Errorf("node %q missing", id)
			continue
		}
		if n.GetType() != missionv1.NodeType_NODE_TYPE_TOOL {
			t.Errorf("node %q type = %v, want TOOL", id, n.GetType())
		}
		if got := n.GetToolConfig().GetToolName(); got != tool {
			t.Errorf("node %q tool = %q, want %q", id, got, tool)
		}
	}

	src, ok := nodes["source"]
	if !ok {
		t.Fatal("source node missing")
	}
	if src.GetType() != missionv1.NodeType_NODE_TYPE_AGENT {
		t.Errorf("source type = %v, want AGENT", src.GetType())
	}
	if got := src.GetAgentConfig().GetAgentName(); got != "zerocool" {
		t.Errorf("source agent = %q, want zerocool", got)
	}

	report, ok := nodes["report"]
	if !ok {
		t.Fatal("report join node missing")
	}
	if report.GetType() != missionv1.NodeType_NODE_TYPE_JOIN {
		t.Errorf("report type = %v, want JOIN", report.GetType())
	}
}

func TestRender_EveryToolItNamesIsInTheCatalog(t *testing.T) {
	// A mission naming a tool the platform does not ship fails at dispatch,
	// per node, at runtime — long after the render looked fine. Catch it here.
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	shipped := map[string]bool{
		"nmap": true, "naabu": true, "masscan": true, "httpx": true,
		"nuclei": true, "subfinder": true, "dnsx": true, "trivy": true, "tlsx": true,
	}
	for id, n := range def.GetNodes() {
		if n.GetType() != missionv1.NodeType_NODE_TYPE_TOOL {
			continue
		}
		if name := n.GetToolConfig().GetToolName(); !shipped[name] {
			t.Errorf("node %q names tool %q, which the executor does not ship", id, name)
		}
	}
}

func TestRender_ParametersReachTheNodesThatNeedThem(t *testing.T) {
	p := validParams()
	def, err := Render(context.Background(), "scan", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The image node scans the image the pipeline published. A parameter that
	// does not arrive here scans the wrong thing rather than failing.
	if got := def.GetNodes()["image"].GetToolConfig().GetInput()["image"]; got != p["imageRef"] {
		t.Errorf("image input = %q, want %q", got, p["imageRef"])
	}

	// The agent inherits the provenance of the scan. Checked by key, because a
	// context that silently loses a key produces an agent that scans HEAD.
	ctxMap := def.GetNodes()["source"].GetAgentConfig().GetTask().GetContext()
	for key, want := range map[string]string{
		"application":       p["application"],
		"repository.commit": p["commit"],
		"repository.url":    p["repositoryUrl"],
		"repository.ref":    p["ref"],
		"pipeline.id":       p["pipelineId"],
		"pipeline.url":      p["pipelineUrl"],
		"image.ref":         p["imageRef"],
		"zerocool.task":     "source-analysis",
	} {
		v, ok := ctxMap[key]
		if !ok {
			t.Errorf("task context is missing %q", key)
			continue
		}
		if got := v.GetStringValue(); got != want {
			t.Errorf("task context %q = %q, want %q", key, got, want)
		}
	}

	if goal := def.GetNodes()["source"].GetAgentConfig().GetTask().GetGoal(); !strings.Contains(goal, p["commit"]) {
		t.Errorf("goal does not name the commit it must scan: %q", goal)
	}
}

func TestRender_RuntimeBranchTakesItsHostFromTheTargetNotAParameter(t *testing.T) {
	// A caller must not be able to point a scan at a host the tenant has not
	// registered. The runtime nodes read the mission's bound target instead.
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, id := range []string{"ports", "services", "web", "tls"} {
		input := def.GetNodes()[id].GetToolConfig().GetInput()
		var found bool
		for _, v := range input {
			if strings.Contains(v, "{{target.") {
				found = true
			}
		}
		if !found {
			t.Errorf("node %q does not read the bound target: %v", id, input)
		}
	}
}

func TestRender_AQuoteInAParameterCannotInjectCUE(t *testing.T) {
	p := validParams()
	p["application"] = `x" , injected: "yes`
	def, err := Render(context.Background(), "scan", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := def.GetNodes()["source"].GetAgentConfig().GetTask().GetContext()["application"].GetStringValue()
	if got != p["application"] {
		t.Errorf("application = %q, want the value verbatim %q", got, p["application"])
	}
}

// TestRender_EveryTargetPlaceholderIsInTheVocabulary closes the loop the test
// above leaves open. That one asserts a placeholder is present, which a typo
// satisfies just as well as a real binding. This one asserts each placeholder is
// a name the binder resolves, so a catalog mission cannot ship a placeholder
// that nothing will ever replace (gibson#495).
func TestRender_EveryTargetPlaceholderIsInTheVocabulary(t *testing.T) {
	for _, name := range Names() {
		def, err := Render(context.Background(), name, validParams())
		if err != nil {
			t.Fatalf("Render(%s): %v", name, err)
		}
		for _, left := range targetbind.Unbound(def) {
			// Unbound formats "<field path>: {{name}}". Cut at the delimiter
			// rather than indexing it: Index returns -1 when absent, and slicing
			// on that panics instead of reporting the surprise.
			_, ref, found := strings.Cut(left, targetbind.Open)
			if !found {
				t.Errorf("Unbound returned %q with no %s in it", left, targetbind.Open)
				continue
			}
			ref = strings.TrimSuffix(ref, targetbind.Close)
			if !strings.HasPrefix(ref, targetbind.Prefix) {
				continue // another namespace, not this check's business
			}
			if !targetbind.Known(ref) {
				t.Errorf("mission %q: %s names no target field; the bindings are %v",
					name, left, targetbind.Names())
			}
		}
	}
}

// And the binder must actually resolve them, against a target shaped like the
// one a run names. A vocabulary check passes on a placeholder the binder would
// still refuse for being empty on the target.
func TestRender_ScanBindsAgainstARegisteredTarget(t *testing.T) {
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	tgt := types.NewTarget("kubernetes-goat", "https://goat.internal:8080", types.TargetTypeCustom)

	bound, err := targetbind.Bind(def, tgt)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if left := targetbind.UnboundTarget(bound); len(left) > 0 {
		t.Fatalf("placeholders survived binding: %v", left)
	}
	for _, id := range []string{"ports", "services", "web", "tls"} {
		for key, value := range bound.GetNodes()[id].GetToolConfig().GetInput() {
			if strings.Contains(value, "goat.internal") {
				continue
			}
			if strings.Contains(value, targetbind.Open) {
				t.Errorf("node %q input %q still carries a placeholder: %q", id, key, value)
			}
		}
	}
}

// TestRender_ScanMatchesItsRecordedRender pins the whole rendered definition,
// not a field of it.
//
// It was added with the move to per-mission parameters (gibson#499) to prove
// that change was a refactor: the bytes here were produced by the code BEFORE
// it, and they did not move. After that, it keeps earning its place — a mission
// is a work graph, and a change to it should be a change somebody chose, visible
// as a diff in this file rather than discovered on a run.
//
// Regenerate deliberately, and read the diff as the review:
//
//	go test ./internal/platform/missioncatalog/ -run ScanMatchesItsRecordedRender -update
func TestRender_ScanMatchesItsRecordedRender(t *testing.T) {
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(def)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	const golden = "testdata/scan-rendered.json"
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatalf("write %s: %v", golden, err)
		}
		t.Logf("updated %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v", golden, err)
	}
	// protojson's output carries deliberate randomised whitespace (detrand), so
	// the comparison normalises it rather than asserting on bytes nobody chose.
	if normalizeJSON(t, got) != normalizeJSON(t, want) {
		t.Errorf("the scan mission renders differently than recorded.\n"+
			"If that is the change you meant, re-run with -update and the diff is the review.\n"+
			"got:\n%s", got)
	}
}

// normalizeJSON re-encodes through a generic map, which drops protojson's
// randomised indentation and orders keys.
func normalizeJSON(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("the recorded render is not JSON: %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return string(out)
}
