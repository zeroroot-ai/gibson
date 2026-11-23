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

// A Finding whose parent is a Package is placed at the Image of its discovery,
// and the Package is data. A Package is shared by many images, so it is never
// the place (gibson#1469).
func TestDiscoveryEvents_AFindingIsPlacedAtItsImageAndNamesItsPackage(t *testing.T) {
	const pkg = "pkg:apk/alpine/libx@1.0"
	events, _ := discoveryEvents(ExecContext{MissionID: "m1"}, trivyShape("sha256:aa", pkg))
	w := brain.NewWorld("acme")
	for _, e := range events {
		brain.Reduce(w, e)
	}
	findings := w.FindingSnapshot()
	require.Len(t, findings, 1)
	assert.Equal(t, []brain.FindingPlace{{Label: "Image", Key: "sha256:aa"}}, findings[0].Places)
	assert.Equal(t, []string{pkg}, findings[0].Packages)

	keys := map[string]string{}
	for _, e := range w.EntitySnapshot() {
		keys[e.Label] = e.Key
	}
	assert.Equal(t, keys["Image"], findings[0].Places[0].Key, "the place meets the Image node on one key")
	assert.Equal(t, keys["Package"], findings[0].Packages[0], "the Finding meets the Package node on one key")
}

// A Finding with a parent that is no Package, and a Finding with no parent, get
// no place and no Package.
func TestDiscoveryEvents_AFindingOfNoPackageHasNoPlace(t *testing.T) {
	d := trivyShape("sha256:aa", "pkg:apk/alpine/libx@1.0")
	d.Findings[0].ParentId = proto.String("some-host-id")
	d2 := trivyShape("sha256:aa", "pkg:apk/alpine/libx@1.0")
	d2.Findings[0].ParentId = nil
	for _, disc := range []*graphragpb.DiscoveryResult{d, d2} {
		events, _ := discoveryEvents(ExecContext{MissionID: "m1"}, disc)
		for _, e := range events {
			if f, ok := e.(brain.FindingRaised); ok {
				assert.Empty(t, f.Places)
				assert.Empty(t, f.Packages)
			}
		}
	}
}

// A re-raise of a known Finding from another place adds that place. The place that
// the Finding had stays, and a place is added once.
func TestFindingRaised_AReRaiseAddsThePlace(t *testing.T) {
	w := brain.NewWorld("acme")
	raise := func(image string) {
		brain.Reduce(w, brain.FindingRaised{
			ID: "f1", Title: "t", Status: brain.FindingStatusOpen,
			Places: []brain.FindingPlace{{Label: "Image", Key: image}}, Packages: []string{"pkg:x"},
		})
	}
	raise("sha256:aa")
	raise("sha256:bb")
	raise("sha256:bb")
	f := w.FindingSnapshot()[0]
	assert.Equal(t, []brain.FindingPlace{{Label: "Image", Key: "sha256:aa"}, {Label: "Image", Key: "sha256:bb"}}, f.Places)
	assert.Equal(t, []string{"pkg:x"}, f.Packages)
}

// A Package that names an Image that the discovery did not report places its
// Finding nowhere, and the Package stays as data.
func TestDiscoveryEvents_APackageOfAnUnknownImageGivesNoPlace(t *testing.T) {
	d := trivyShape("sha256:aa", "pkg:apk/alpine/libx@1.0")
	d.CustomNodes = d.CustomNodes[1:] // drop the Image node
	events, _ := discoveryEvents(ExecContext{MissionID: "m1"}, d)
	for _, e := range events {
		if f, ok := e.(brain.FindingRaised); ok {
			assert.Empty(t, f.Places)
			assert.Equal(t, []string{"pkg:apk/alpine/libx@1.0"}, f.Packages)
		}
	}
}
