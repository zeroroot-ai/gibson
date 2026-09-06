// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"strings"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func validParams() Params {
	return Params{
		Application:   "customer-portal",
		RepositoryURL: "https://gitlab.com/examplebank/customer-portal.git",
		Ref:           "main",
		Commit:        "0123456789abcdef0123456789abcdef01234567",
		PipelineID:    "8891",
		PipelineURL:   "https://gitlab.com/examplebank/customer-portal/-/pipelines/8891",
		ImageRef:      "registry.gitlab.com/examplebank/customer-portal@sha256:abc",
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
	_, err := Render(context.Background(), "scan", Params{Application: "customer-portal"})
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
	p.Commit = "   "
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
	if got := def.GetNodes()["image"].GetToolConfig().GetInput()["image"]; got != p.ImageRef {
		t.Errorf("image input = %q, want %q", got, p.ImageRef)
	}

	// The agent inherits the provenance of the scan. Checked by key, because a
	// context that silently loses a key produces an agent that scans HEAD.
	ctxMap := def.GetNodes()["source"].GetAgentConfig().GetTask().GetContext()
	for key, want := range map[string]string{
		"application":       p.Application,
		"repository.commit": p.Commit,
		"repository.url":    p.RepositoryURL,
		"repository.ref":    p.Ref,
		"pipeline.id":       p.PipelineID,
		"pipeline.url":      p.PipelineURL,
		"image.ref":         p.ImageRef,
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

	if goal := def.GetNodes()["source"].GetAgentConfig().GetTask().GetGoal(); !strings.Contains(goal, p.Commit) {
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
	p.Application = `x" , injected: "yes`
	def, err := Render(context.Background(), "scan", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := def.GetNodes()["source"].GetAgentConfig().GetTask().GetContext()["application"].GetStringValue()
	if got != p.Application {
		t.Errorf("application = %q, want the value verbatim %q", got, p.Application)
	}
}
