// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"net/url"
	"regexp"
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

// scpForm matches the scp-like form of a git remote, user@host:path.
var scpForm = regexp.MustCompile(`^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):(.+)$`)

// repositoryParts returns the host and the path of a repository URL, from the
// https form or the scp-like form. It returns empty strings for any other value.
func repositoryParts(rawURL string) (host, path string) {
	raw := strings.TrimSpace(rawURL)
	if m := scpForm.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "://") {
		return m[1], m[2]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	return u.Hostname(), u.Path
}

// RepositoryKey returns the identity of a repository: its host and its path,
// with no scheme, no user info, no ".git" suffix and no trailing slash, in lower
// case. GitHub and GitLab both treat the host and the path as case-insensitive,
// so two spellings of one repository give one key. It returns "" for a value
// that is not a URL with a host and a path.
func RepositoryKey(rawURL string) string {
	host, path := repositoryParts(rawURL)
	path = strings.Trim(strings.TrimSuffix(strings.TrimRight(path, "/"), ".git"), "/")
	if host == "" || path == "" {
		return ""
	}
	return strings.ToLower(host) + "/" + strings.ToLower(path)
}

// repositoryURL returns the https URL of the repository with no user info, no
// query and no fragment. A clone URL can carry a token in its user info, and the
// World, the Timeline and the graph must never hold it.
func repositoryURL(rawURL string) string {
	key := RepositoryKey(rawURL)
	if key == "" {
		return ""
	}
	return "https://" + key
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
	repoProps := map[string]string{"url": repositoryURL(params[scanParamRepositoryURL])}
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
