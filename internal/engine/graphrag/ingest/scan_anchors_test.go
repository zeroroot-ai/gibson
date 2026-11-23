// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

func scanParams() map[string]string {
	return map[string]string{
		"application": "customer-portal", "repositoryUrl": "https://GitLab.com/examplebank/customer-portal.git",
		"ref": "main", "commit": "abc123", "pipelineId": "7", "pipelineUrl": "https://gitlab.com/p/7",
		"imageRef": "registry.example.com/portal@sha256:" + "ab12",
	}
}

func TestScanAnchorEvents_LinkTheApplicationToTheRepositoryAndTheImage(t *testing.T) {
	evs := ScanAnchorEvents(scanParams(), "mission-1")
	require.Len(t, evs, 3)
	byLabel := map[string]brain.EntityObserved{}
	for _, e := range evs {
		eo, ok := e.(brain.EntityObserved)
		require.True(t, ok)
		assert.Equal(t, "mission-1", eo.MissionID)
		byLabel[eo.Label] = eo
	}
	assert.Equal(t, "gitlab.com/examplebank/customer-portal", byLabel["Repository"].Key)
	app := byLabel["Application"]
	assert.Equal(t, "customer-portal", app.Key)
	assert.Equal(t, []brain.EntityEdge{{Type: "HAS_REPOSITORY", TargetLabel: "Repository", TargetKey: "gitlab.com/examplebank/customer-portal"}}, app.Edges)
	img := byLabel["Image"]
	assert.Equal(t, "sha256:ab12", img.Key, "the key is the digest, as the scan tool keys its Image node")
	assert.Equal(t, []brain.EntityEdge{{Type: "BUILT_FROM", TargetLabel: "Repository", TargetKey: "gitlab.com/examplebank/customer-portal"}}, img.Edges)
	assert.Equal(t, "abc123", img.Props["commit"])
}

// Every label and edge type is in the Taxonomy, so the projector admits them.
func TestScanAnchorEvents_UseTheTaxonomy(t *testing.T) {
	for _, e := range ScanAnchorEvents(scanParams(), "m") {
		eo := e.(brain.EntityObserved)
		assert.True(t, taxonomy.Global.ClassifyNode(eo.Label).InTaxonomy, eo.Label)
		for _, edge := range eo.Edges {
			assert.True(t, taxonomy.Global.ClassifyRelationship(edge.Type).InTaxonomy, edge.Type)
		}
	}
}

// A parameter that names no usable node gives no edge: a guessed edge would link
// a finding to the wrong Application.
func TestScanAnchorEvents_RefuseWhatTheyCannotName(t *testing.T) {
	for name, mut := range map[string]func(map[string]string){
		"no application": func(p map[string]string) { delete(p, "application") },
		"blank":          func(p map[string]string) { p["application"] = "  " },
		"no repository":  func(p map[string]string) { delete(p, "repositoryUrl") },
		"not a url":      func(p map[string]string) { p["repositoryUrl"] = "not a url" },
		"host only":      func(p map[string]string) { p["repositoryUrl"] = "https://gitlab.com/" },
	} {
		t.Run(name, func(t *testing.T) {
			p := scanParams()
			mut(p)
			assert.Empty(t, ScanAnchorEvents(p, "m"))
		})
	}
	// An image with a tag only has no digest, so the Image gets no edge.
	p := scanParams()
	p["imageRef"] = "registry.example.com/portal:1.2.3"
	evs := ScanAnchorEvents(p, "m")
	require.Len(t, evs, 2)
	for _, e := range evs {
		assert.NotEqual(t, "Image", e.(brain.EntityObserved).Label)
	}
}

func TestRepositoryKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/acme/shop":          "github.com/acme/shop",
		"https://user:pw@github.com/acme/shop/": "github.com/acme/shop",
		"https://gitlab.com/a/b/c.git":          "gitlab.com/a/b/c",
		"":                                      "",
		"https://x.example":                     "",
	} {
		assert.Equal(t, want, RepositoryKey(in), in)
	}
}
