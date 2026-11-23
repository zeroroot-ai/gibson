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

// defaultPorts are the ports that a scheme uses when the URL names none. A URL
// that names the default port is the same repository as one that does not.
var defaultPorts = map[string]string{"https": "443", "http": "80", "ssh": "22", "git+ssh": "22", "ssh+git": "22", "git": "9418"}

// repositoryParts returns the host and the path of a repository URL, from the
// URL form or the scp-like form. The host has no default port of its scheme and
// no trailing dot, and any other port stays. It returns empty strings for any
// other value.
func repositoryParts(rawURL string) (host, path string) {
	raw := strings.TrimSpace(rawURL)
	if m := scpForm.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "://") {
		return strings.TrimSuffix(m[1], "."), m[2]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	name := strings.TrimSuffix(u.Hostname(), ".")
	if strings.Contains(name, ":") {
		name = "[" + name + "]" // an IPv6 address keeps its brackets before a port
	}
	if port := u.Port(); port != "" && port != defaultPorts[strings.ToLower(u.Scheme)] {
		return name + ":" + port, u.Path
	}
	return name, u.Path
}

// RepositoryKey returns the identity of a repository: its host and its path,
// with no scheme, no user info, no ".git" suffix and no trailing slash. The host
// is in lower case, because a host name is case-insensitive. The path is kept as
// given, because some Git hosts (Gerrit, cgit, CodeCommit) treat it as case
// sensitive, and two repositories must not become one node. Two spellings of one
// repository on a case-insensitive host give two keys, and each scan writes both
// ends of its edges from the same parameters, so that is safe. It returns "" for
// a value that is not a URL with a host and a path.
func RepositoryKey(rawURL string) string {
	host, path := repositoryParts(rawURL)
	path = strings.Trim(strings.TrimSuffix(strings.TrimRight(path, "/"), ".git"), "/")
	if host == "" || path == "" {
		return ""
	}
	return strings.ToLower(host) + "/" + path
}

// repositoryURL returns the URL of the repository with no user info, no query
// and no fragment, built from the parsed URL so the scheme, the port and the case
// stay. A clone URL can carry a token in its user info, and the World, the
// Timeline and the graph must never hold it. The scp form has no URL, and it
// stores none.
func repositoryURL(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	if scpForm.MatchString(raw) && !strings.Contains(raw, "://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	u.User = nil
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u.String()
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
	repoProps := map[string]string{}
	if u := repositoryURL(params[scanParamRepositoryURL]); u != "" {
		repoProps["url"] = u
	}
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
