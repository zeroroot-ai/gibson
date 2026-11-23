// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// dependency_alerts.go maps the result of the connector tool list_dependency_alerts
// (zeroroot-ai/connectors, github-fixloop and gitlab-fixloop) to the events of the
// World. The alerts are the buyer's own read of its dependencies, so the check that
// raises a finding here is a read of a tool of the buyer (finding.CheckTool). The
// same tool says when an alert is fixed, and that is the only thing that verifies
// the finding. A scan that does not re-raise an alert verifies nothing
// (brain.RescanReconciliationSystem skips a tool finding).
//
// The rules (gibson#1469):
//
//   - An open alert raises a Finding. The Finding is keyed on the advisory id (GHSA,
//     else CVE), the package name and the ecosystem, and never on the purl: the purl
//     holds the version, and a fix changes it.
//   - The Finding is placed at the Repository of the scan. The Package, keyed by the
//     purl as the trivy parser keys it, stays as data (IN_PACKAGE).
//   - An alert with state fixed verifies its Finding, but only from a call with
//     state "all" and a list that is not truncated, and only when the alert is
//     verifiable: it has an advisory id and an ecosystem, and its package has one version.
//   - A dismissed alert verifies nothing. It waits for a person, and the result says
//     so. An alert gone from the list verifies nothing either.
//   - An alert that is not verifiable raises a Finding and never verifies it, and
//     the result says why.

// DependencyAlertsTool is the name of the connector tool.
const DependencyAlertsTool = "list_dependency_alerts"

// dependencyAlertsResult is the result of list_dependency_alerts.
type dependencyAlertsResult struct {
	Project string `json:"project"`
	// State is the state that the call asked for. Only a call with state "all"
	// can verify a Finding.
	State     string            `json:"state"`
	Truncated bool              `json:"truncated"`
	Alerts    []dependencyAlert `json:"alerts"`
}

type dependencyAlert struct {
	ID                  string   `json:"id"`
	State               string   `json:"state"`
	Package             string   `json:"package"`
	Ecosystem           string   `json:"ecosystem"`
	PURL                string   `json:"purl"`
	Version             string   `json:"version"`
	AdvisoryIDs         []string `json:"advisory_ids"`
	Severity            string   `json:"severity"`
	ManifestPath        string   `json:"manifest_path"`
	VulnerableRange     string   `json:"vulnerable_version_range"`
	FirstPatchedVersion string   `json:"first_patched_version"`
	URL                 string   `json:"url"`
	// Verifiable is false when the alert has no advisory id. Nil (an older tool)
	// means that the advisory id decides.
	Verifiable *bool `json:"verifiable"`
	// VersionAmbiguous is true when the package is installed at several versions.
	// The version and the purl are then empty.
	VersionAmbiguous bool     `json:"version_ambiguous"`
	Versions         []string `json:"versions"`
}

// DependencyAlertOutcome is what the mapping made of one result.
type DependencyAlertOutcome struct {
	// Events are the events to submit, in order: the Package entities, then the
	// Findings, then the reruns.
	Events []brain.Event
	// Notes say why an alert verified nothing, or got no Package. The caller logs
	// them. They are for a person.
	Notes []string
}

// advisoryOf returns the advisory id that keys a Finding: the GHSA id, else the
// CVE id, else "".
func advisoryOf(ids []string) string {
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "GHSA-") {
			return id
		}
	}
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			return id
		}
	}
	return ""
}

var dependencyAlertNamespace = uuid.MustParse("3c0b1d7e-5e0a-4f6a-9a53-7a3f2b1c9d10")

// DependencyAlertFindingID returns the identity of the Finding of an alert. It is
// stable across a fix: it holds the repository, the advisory, the ecosystem, the
// package name and the manifest path, and no version. One advisory can name a
// package in two manifests, and the fix of one must not verify the other. An alert with no advisory id is keyed on the
// id of the alert.
func DependencyAlertFindingID(repoKey, advisory, ecosystem, pkg, manifest, alertID string) string {
	key := fmt.Sprintf("alert|%s|%s|%s|%s|%s", repoKey, advisory, ecosystem, pkg, manifest)
	if advisory == "" {
		key = fmt.Sprintf("alert|%s|id|%s", repoKey, alertID)
	}
	return uuid.NewSHA1(dependencyAlertNamespace, []byte(key)).String()
}

// DependencyAlertEvents maps the result of list_dependency_alerts to events. The
// result is the decoded JSON of the tool. repoKey is the key of the Repository of
// the scan (RepositoryKey). It returns an error when the result is not the shape
// of the tool.
func DependencyAlertEvents(result any, repoKey, missionID, runID string, now time.Time) (DependencyAlertOutcome, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return DependencyAlertOutcome{}, fmt.Errorf("encode the result of %s: %w", DependencyAlertsTool, err)
	}
	var res dependencyAlertsResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return DependencyAlertOutcome{}, fmt.Errorf("the result of %s is not the shape of the tool: %w", DependencyAlertsTool, err)
	}
	if repoKey == "" {
		return DependencyAlertOutcome{}, fmt.Errorf("the scan has no Repository, so a Finding of %s has no place", DependencyAlertsTool)
	}
	var out DependencyAlertOutcome
	// A truncated list may miss an alert, and a call with another state than "all"
	// does not list the fixed alerts. No alert verifies anything then.
	complete := !res.Truncated && strings.EqualFold(res.State, "all")
	if res.Truncated {
		out.Notes = append(out.Notes, "the list of alerts is truncated, so no alert verifies a finding")
	}
	if !strings.EqualFold(res.State, "all") {
		out.Notes = append(out.Notes, fmt.Sprintf("the call asked for state %q and not \"all\", so no alert verifies a finding", res.State))
	}

	var packages, findings, reruns []brain.Event
	seenPackage := map[string]bool{}
	for _, a := range res.Alerts {
		advisory := advisoryOf(a.AdvisoryIDs)
		id := DependencyAlertFindingID(repoKey, advisory, a.Ecosystem, a.Package, a.ManifestPath, a.ID)
		switch strings.ToLower(a.State) {
		case "open":
			var pkgs []string
			if a.PURL == "" {
				out.Notes = append(out.Notes, fmt.Sprintf("alert %s has no purl (the version is unknown), so its Finding has no Package", a.ID))
			} else {
				pkgs = []string{a.PURL}
				if !seenPackage[a.PURL] {
					seenPackage[a.PURL] = true
					packages = append(packages, brain.EntityObserved{
						Label: "Package", Key: a.PURL, MissionID: missionID, MissionRunID: runID,
						Props: map[string]string{"name": a.Package, "version": a.Version, "ecosystem": a.Ecosystem},
					})
				}
			}
			if !verifiable(a, advisory) {
				out.Notes = append(out.Notes, notVerifiableReason(a, advisory))
			}
			title := fmt.Sprintf("%s in %s %s", firstNonEmpty(advisory, "dependency alert "+a.ID), a.Package, a.Version)
			findings = append(findings, brain.FindingRaised{
				ID: id, Title: strings.TrimSpace(title), Description: alertDescription(a),
				Severity: strings.ToLower(a.Severity), ScopeID: missionID, MissionID: missionID, MissionRunID: runID,
				Status: brain.FindingStatusOpen, VulnerabilityID: advisory,
				Places:   []brain.FindingPlace{{Label: "Repository", Key: repoKey}},
				Packages: pkgs,
				// The alert is a read of a tool of the buyer. That read verifies the fix.
				CheckKind: string(finding.CheckTool), CheckRef: DependencyAlertsTool,
				At: now,
			})
			if verifiable(a, advisory) {
				// The alert is open: a fix that was merged did not hold.
				reruns = append(reruns, brain.CheckRerun{
					ID: id, CheckKind: string(finding.CheckTool), Found: true, EvidenceAt: now, MissionID: missionID,
				})
			}
		case "fixed":
			switch {
			case !verifiable(a, advisory):
				out.Notes = append(out.Notes, notVerifiableReason(a, advisory)+", so it verifies nothing")
			case !complete:
				// The note above says why.
			default:
				reruns = append(reruns, brain.CheckRerun{
					ID: id, CheckKind: string(finding.CheckTool), Found: false, EvidenceAt: now, MissionID: missionID,
				})
			}
		default:
			// dismissed, auto_dismissed or a state that this release does not know.
			out.Notes = append(out.Notes, fmt.Sprintf("alert %s is %s: it verifies nothing and waits for a person", a.ID, a.State))
		}
	}
	out.Events = append(append(packages, findings...), reruns...)
	return out, nil
}

// verifiable reports whether an alert can verify or reopen its Finding: it names
// an advisory, the tool did not mark it not verifiable, and its package has one
// version.
func verifiable(a dependencyAlert, advisory string) bool {
	if advisory == "" || a.VersionAmbiguous || strings.TrimSpace(a.Ecosystem) == "" {
		return false
	}
	return a.Verifiable == nil || *a.Verifiable
}

func notVerifiableReason(a dependencyAlert, advisory string) string {
	switch {
	case advisory == "" || (a.Verifiable != nil && !*a.Verifiable):
		return fmt.Sprintf("alert %s has no advisory id", a.ID)
	case strings.TrimSpace(a.Ecosystem) == "":
		return fmt.Sprintf("alert %s has no ecosystem", a.ID)
	case a.VersionAmbiguous:
		return fmt.Sprintf("alert %s: the package is installed at several versions (%s)", a.ID, strings.Join(a.Versions, ", "))
	}
	return fmt.Sprintf("alert %s is not verifiable", a.ID)
}

func alertDescription(a dependencyAlert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Dependency alert %s: %s %s (%s)", a.ID, a.Package, a.Version, a.Ecosystem)
	if a.ManifestPath != "" {
		fmt.Fprintf(&b, " in %s", a.ManifestPath)
	}
	if len(a.AdvisoryIDs) > 0 {
		fmt.Fprintf(&b, ". Advisories: %s", strings.Join(a.AdvisoryIDs, ", "))
	}
	if a.VulnerableRange != "" {
		fmt.Fprintf(&b, ". Vulnerable: %s", a.VulnerableRange)
	}
	if a.FirstPatchedVersion != "" {
		fmt.Fprintf(&b, ". First patched version: %s", a.FirstPatchedVersion)
	}
	return b.String()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
