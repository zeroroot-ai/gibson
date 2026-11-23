// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"net/url"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// scan_anchors.go anchors the findings of a scan mission to their Application.
//
// The scan mission names the Application, its repository and the image that the
// pipeline built (internal/platform/missioncatalog/missions/scan.cue). The scan
// tools report Image, Package, Vulnerability and Finding nodes, and none of them
// knows the Application. Without a link from the Image to the Application,
// FindingPlaces finds no place for a finding, and the fix loop never grants a
// merge slot for it (finding_place.go, applicationReachesPlace).
//
// This file turns the parameters of the mission into the two edges that route
// (app)-[:HAS_REPOSITORY]->(:Repository)<-[:BUILT_FROM]-(:Image) needs. It reads
// the parameters only. It never reads a tool result, so no tool can name an
// Application that the mission did not name.

// The parameter names of the scan mission and the labels and edges of the
// Taxonomy (internal/engine/taxonomy/taxonomy.go).
const (
	scanParamApplication   = "application"
	scanParamRepositoryURL = "repositoryUrl"
	scanParamRef           = "ref"
	scanParamCommit        = "commit"
	scanParamImageRef      = "imageRef"

	labelApplication = "Application"
	labelRepository  = "Repository"
	labelImage       = "Image"
	edgeHasRepo      = "HAS_REPOSITORY"
	edgeBuiltFrom    = "BUILT_FROM"
)

// RepositoryKey returns the identity of a repository: its host and its path,
// with no scheme, no user info, no ".git" suffix and no trailing slash. It
// returns "" for a value that is not a URL with a host and a path.
func RepositoryKey(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	path := strings.Trim(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git"), "/")
	if path == "" {
		return ""
	}
	return strings.ToLower(u.Hostname()) + "/" + path
}

// ImageDigest returns the digest of an image reference that names one
// (<repository>@sha256:<hex>), and "" for a reference with only a tag. The scan
// tool keys its Image node by the digest, so a tag cannot name that node.
func ImageDigest(imageRef string) string {
	_, digest, ok := strings.Cut(strings.TrimSpace(imageRef), "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") || len(digest) <= len("sha256:") {
		return ""
	}
	return digest
}

// ScanAnchorEvents returns the events that anchor a scan to its Application. It
// returns none when the Application or the repository is missing or unusable,
// because an edge to a guessed node would link a finding to the wrong
// Application. A reference to an image with no digest gets no Image edge.
func ScanAnchorEvents(params map[string]string, missionID string) []brain.Event {
	app := strings.TrimSpace(params[scanParamApplication])
	repo := RepositoryKey(params[scanParamRepositoryURL])
	if app == "" || repo == "" {
		return nil
	}
	repoProps := map[string]string{"url": strings.TrimSpace(params[scanParamRepositoryURL])}
	events := []brain.Event{
		brain.EntityObserved{Label: labelRepository, Key: repo, MissionID: missionID, Props: repoProps},
		brain.EntityObserved{
			Label: labelApplication, Key: app, MissionID: missionID,
			Edges: []brain.EntityEdge{{Type: edgeHasRepo, TargetLabel: labelRepository, TargetKey: repo}},
		},
	}
	if digest := ImageDigest(params[scanParamImageRef]); digest != "" {
		props := map[string]string{}
		if c := strings.TrimSpace(params[scanParamCommit]); c != "" {
			props["commit"] = c
		}
		if r := strings.TrimSpace(params[scanParamRef]); r != "" {
			props["ref"] = r
		}
		events = append(events, brain.EntityObserved{
			Label: labelImage, Key: digest, MissionID: missionID, Props: props,
			Edges: []brain.EntityEdge{{Type: edgeBuiltFrom, TargetLabel: labelRepository, TargetKey: repo}},
		})
	}
	return events
}
