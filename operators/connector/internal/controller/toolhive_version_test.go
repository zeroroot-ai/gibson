// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"os"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// toolhiveServedVersions is the file that scripts/toolhive-served-versions.sh
// writes from one release of the ToolHive CRD chart.
type toolhiveServedVersions struct {
	Chart   string        `json:"chart"`
	Version string        `json:"version"`
	CRDs    []toolhiveCRD `json:"crds"`
}

// toolhiveCRD is the served versions of one ToolHive kind.
type toolhiveCRD struct {
	Kind    string   `json:"kind"`
	Group   string   `json:"group"`
	Served  []string `json:"served"`
	Storage string   `json:"storage"`
}

// The operator creates MCPServer and MCPRemoteProxy at toolhiveAPIVersion. The
// test fails when the pinned chart release does not serve that version for
// each kind, or when the file describes a different chart release
// (gibson#680).
func TestToolHiveAPIVersion_IsServedByThePinnedChart(t *testing.T) {
	raw, err := os.ReadFile("testdata/toolhive-served-versions.yaml")
	if err != nil {
		t.Fatalf("read the served versions: %v", err)
	}
	var got toolhiveServedVersions
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse the served versions: %v", err)
	}
	if got.Chart != "toolhive-operator-crds" || got.Version != toolhiveChartVersion {
		t.Fatalf("the served versions describe %s %s, want toolhive-operator-crds %s; run scripts/toolhive-served-versions.sh %s",
			got.Chart, got.Version, toolhiveChartVersion, toolhiveChartVersion)
	}
	group, version, ok := strings.Cut(toolhiveAPIVersion, "/")
	if !ok {
		t.Fatalf("toolhiveAPIVersion %q has no group", toolhiveAPIVersion)
	}
	for _, kind := range []string{kindMCPServer, kindMCPRemoteProxy} {
		i := slices.IndexFunc(got.CRDs, func(c toolhiveCRD) bool { return c.Kind == kind })
		if i < 0 {
			t.Errorf("chart %s has no CRD for %s", toolhiveChartVersion, kind)
			continue
		}
		crd := got.CRDs[i]
		if crd.Group != group || !slices.Contains(crd.Served, version) {
			t.Errorf("chart %s serves %s %s at %v, want %s", toolhiveChartVersion, crd.Group, kind, crd.Served, toolhiveAPIVersion)
		}
	}
}
