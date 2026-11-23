// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
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
	for in, want := range map[string]string{ //nolint:gosec // fake user info in a URL test
		"https://github.com/acme/shop":              "github.com/acme/shop",
		"https://github.com:443/acme/shop":          "github.com/acme/shop",
		"http://github.com:80/acme/shop":            "github.com/acme/shop",
		"ssh://git@github.com/acme/shop.git":        "github.com/acme/shop",
		"ssh://git@github.com:22/acme/shop.git":     "github.com/acme/shop",
		"git@github.com:acme/shop.git":              "github.com/acme/shop",
		"git+ssh://git@github.com:22/acme/shop.git": "github.com/acme/shop",
		"ssh+git://git@github.com/acme/shop.git":    "github.com/acme/shop",
		"https://[2001:db8::1]:8443/Team/Api":       "[2001:db8::1]:8443/Team/Api",
		"https://github.com./acme/shop":             "github.com/acme/shop",
		"https://git.bank.internal:8443/Team/Api":   "git.bank.internal:8443/Team/Api",
		"git@gitlab.com:Group/Project.git":          "gitlab.com/Group/Project",
		"https://GitHub.com/Acme/Shop":              "github.com/Acme/Shop",
		"https://user:pw@github.com/acme/shop/":     "github.com/acme/shop",
		"https://gitlab.com/a/b/c.git":              "gitlab.com/a/b/c",
		"":                                          "",
		"https://x.example":                         "",
	} {
		assert.Equal(t, want, RepositoryKey(in), in)
	}
}

// A clone URL can carry a token in its user info. The Repository node holds the
// URL, and the World, the Timeline and the graph must hold none of it.
func TestScanAnchorEvents_HoldNoUserInfo(t *testing.T) { //nolint:gosec // G101: the URL holds fake user info on purpose
	p := scanParams()
	p["repositoryUrl"] = "https://gitlab-ci-token:glpat-SECRET@gitlab.com/examplebank/customer-portal.git?private_token=SECRET#frag"
	for _, e := range ScanAnchorEvents(p, "m") {
		eo := e.(brain.EntityObserved)
		var blob strings.Builder
		blob.WriteString(eo.Label + eo.Key)
		for k, v := range eo.Props {
			blob.WriteString(k + v)
		}
		for _, edge := range eo.Edges {
			blob.WriteString(edge.TargetKey)
		}
		if got := blob.String(); strings.Contains(got, "SECRET") || strings.Contains(got, "gitlab-ci-token") {
			t.Errorf("%s holds the user info: %q", eo.Label, got)
		}
	}
	for _, e := range ScanAnchorEvents(p, "m") {
		if eo := e.(brain.EntityObserved); eo.Label == "Repository" && eo.Props["url"] != "https://gitlab.com/examplebank/customer-portal.git" {
			t.Errorf("url = %q", eo.Props["url"])
		}
	}
	// The port and the case stay. The scp form has no URL to store.
	p["repositoryUrl"] = "https://user:pw@Git.Example.com:8443/Team/Repo.git"
	for _, e := range ScanAnchorEvents(p, "m") {
		if eo := e.(brain.EntityObserved); eo.Label == "Repository" {
			assert.Equal(t, "https://Git.Example.com:8443/Team/Repo.git", eo.Props["url"])
			assert.Equal(t, "git.example.com:8443/Team/Repo", eo.Key)
		}
	}
	p["repositoryUrl"] = "git@gitlab.com:examplebank/customer-portal.git"
	for _, e := range ScanAnchorEvents(p, "m") {
		if eo := e.(brain.EntityObserved); eo.Label == "Repository" {
			_, has := eo.Props["url"]
			assert.False(t, has, "the scp form stores no url")
		}
	}
}

// Two repositories whose paths differ only in case are two nodes, because a Git
// host can treat the path as case sensitive.
func TestRepositoryKey_KeepsTheCaseOfThePath(t *testing.T) {
	assert.NotEqual(t, RepositoryKey("https://git.example.com/Team/Repo"), RepositoryKey("https://git.example.com/team/repo"))
	assert.Equal(t, RepositoryKey("https://GIT.example.com/Team/Repo"), RepositoryKey("https://git.example.com/Team/Repo"))
}

// The scp form and the https form of one repository give one Repository.
func TestScanAnchorEvents_TwoFormsOfOneRepositoryGiveOneKey(t *testing.T) {
	a, b := scanParams(), scanParams()
	a["repositoryUrl"] = "git@GitLab.com:examplebank/customer-portal.git"
	b["repositoryUrl"] = "https://gitlab.com/examplebank/customer-portal"
	ea, eb := ScanAnchorEvents(a, "m"), ScanAnchorEvents(b, "m")
	require.Len(t, ea, 3)
	assert.Equal(t, ea[0].(brain.EntityObserved).Key, eb[0].(brain.EntityObserved).Key)
}

// The Image node of a scan is keyed by the digest, and the scan tool reports it
// as the CustomNode Image with the id property "digest" (gibson-executor
// parsers/trivy, imageDigest). The key of the anchor must equal the key that the
// discovery ingest gives that node, or the anchor links a node that no scan
// writes.
func TestScanAnchorEvents_ImageKeyEqualsTheKeyOfTheScanToolNode(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	disc := &graphragpb.DiscoveryResult{CustomNodes: []*graphragpb.CustomNode{{
		NodeType: "Image", IdProperties: map[string]string{"digest": digest},
		Properties: map[string]string{"name": "registry.example.com/portal:1.2.3"},
	}}}
	scanEvents, _ := entityObservedEvents(ExecContext{MissionID: "m"}, disc)
	require.Len(t, scanEvents, 1)
	scanKey := scanEvents[0].(brain.EntityObserved).Key

	p := scanParams()
	p["imageRef"] = "registry.example.com/portal@" + digest
	var anchorKey string
	for _, e := range ScanAnchorEvents(p, "m") {
		if eo := e.(brain.EntityObserved); eo.Label == "Image" {
			anchorKey = eo.Key
		}
	}
	assert.Equal(t, scanKey, anchorKey)
}
