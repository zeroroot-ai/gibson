// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

func alertResult() map[string]any {
	return map[string]any{"project": "acme/shop", "state": "all", "alerts": []any{map[string]any{
		"id": "dependabot:1", "state": "open", "package": "github.com/acme/lib", "ecosystem": "go",
		"purl": "pkg:golang/github.com/acme/lib@v1.2.0", "version": "v1.2.0", "advisory_ids": []any{"GHSA-xxxx"}, "severity": "high",
	}}}
}

// The mapping reads the Repository that the anchors of this scan wrote, and it
// submits the Findings to the World of the tenant of the mission through the same
// events that a discovery uses. Another tenant sees nothing.
func TestIngestDependencyAlerts_RaisesFindingsAtTheRepositoryOfTheScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	ingestScanAnchors(reg, nil)(ctx, "acme", "scan-1", map[string]string{
		"application": "shop", "repositoryUrl": "https://github.com/acme/shop", "imageRef": "r.example/p@sha256:ab12",
	})
	waitFor(t, func() bool { return len(reg.For("acme").Entities()) == 3 })

	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-1", eng: reg.For("acme")}
	if err := ingestDependencyAlerts(bind, "scan-1", alertResult(), nil); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	waitFor(t, func() bool { return len(reg.For("acme").Findings()) == 1 })
	f := reg.For("acme").Findings()[0]
	if len(f.Places) != 1 || f.Places[0].Label != "Repository" || f.Places[0].Key != "github.com/acme/shop" {
		t.Errorf("places = %+v, want the Repository of the scan", f.Places)
	}
	if len(f.Packages) != 1 || f.CheckKind != "tool" {
		t.Errorf("finding = %+v", f)
	}
	if n := len(reg.For("other").Findings()); n != 0 {
		t.Errorf("another tenant holds %d findings", n)
	}

	// A scan with no Repository has no place for the Findings: the node fails.
	if err := ingestDependencyAlerts(bind, "scan-without-anchors", alertResult(), nil); err == nil {
		t.Error("a mission with no Repository must fail")
	}
	if err := ingestDependencyAlerts(&missionBinding{}, "scan-1", alertResult(), nil); err == nil {
		t.Error("a mission with no World must fail")
	}
}
