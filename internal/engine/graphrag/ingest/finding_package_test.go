// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// trivyShape is the DiscoveryResult of an image scan in the shape of the trivy
// parser (gibson-executor parsers/trivy): an Image, a Package that CONTAINS-links
// to it, and a Finding whose ParentId is the id of the Package.
func trivyShape(digest, pkgID string) *graphragpb.DiscoveryResult {
	return &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{NodeType: "Image", IdProperties: map[string]string{"digest": digest}},
			{
				NodeType: "Package", IdProperties: map[string]string{"id": pkgID},
				ParentType: proto.String("Image"), ParentId: map[string]string{"digest": digest},
				RelationshipType: proto.String("CONTAINS"),
			},
		},
		Findings: []*graphragpb.Finding{{
			Id: proto.String("finding:" + digest + ":" + pkgID + ":CVE-2026-1"), Title: "CVE-2026-1 in libx 1.0",
			Severity: "high", CveIds: proto.String("CVE-2026-1"), ParentId: proto.String(pkgID),
		}},
	}
}

// A Finding whose parent is a Package affects that Package. The key is the key of
// the Package node, so the projector writes AFFECTS to the node that the scan
// wrote (gibson#1469).
func TestDiscoveryEvents_AFindingOfAPackageAffectsThePackage(t *testing.T) {
	const pkg = "pkg:apk/alpine/libx@1.0"
	events, _ := discoveryEvents(ExecContext{MissionID: "m1"}, trivyShape("sha256:aa", pkg))
	w := brain.NewWorld("acme")
	for _, e := range events {
		brain.Reduce(w, e)
	}
	findings := w.FindingSnapshot()
	require.Len(t, findings, 1)
	assert.Equal(t, pkg, findings[0].AffectsPackage)

	var packageKey string
	for _, e := range w.EntitySnapshot() {
		if e.Label == "Package" {
			packageKey = e.Key
		}
	}
	assert.Equal(t, packageKey, findings[0].AffectsPackage, "the Finding and the Package node meet on one key")
}

// A Finding with a parent that is no Package gets no Package edge, and a Finding
// with no parent gets none.
func TestDiscoveryEvents_AFindingOfNoPackageAffectsNoPackage(t *testing.T) {
	d := trivyShape("sha256:aa", "pkg:apk/alpine/libx@1.0")
	d.Findings[0].ParentId = proto.String("some-host-id")
	d2 := trivyShape("sha256:aa", "pkg:apk/alpine/libx@1.0")
	d2.Findings[0].ParentId = nil
	for _, disc := range []*graphragpb.DiscoveryResult{d, d2} {
		events, _ := discoveryEvents(ExecContext{MissionID: "m1"}, disc)
		for _, e := range events {
			if f, ok := e.(brain.FindingRaised); ok {
				assert.Empty(t, f.AffectsPackage)
			}
		}
	}
}
