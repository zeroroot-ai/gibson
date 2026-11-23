// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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
// The rules (gibson#1469). The coordinator of the epic decided the key and the
// verify match, and the owner did not:
//
//   - An open alert raises a Finding. The Finding is keyed on the repository, the
//     advisory id (GHSA, else CVE), the ecosystem, the package name and the
//     manifest path, and never on the purl: the purl holds the version, and a fix
//     changes it. One advisory can name a package in two manifests, and the fix of
//     one must not verify the other, so the manifest path is part of the key.
//   - The Finding is placed at the Repository of the scan. The Package, keyed by
//     the purl as the trivy parser keys it, stays as data (IN_PACKAGE).
//   - A fix can move a package to another manifest (package-lock.json replaced by
//     yarn.lock). The old alert then shows fixed and a new alert opens under the
//     new path. So a Finding verifies only when no alert for the same advisory and
//     package (ecosystem and name) is open in ANY manifest of the repository, and
//     an open alert in another manifest reopens a fixed Finding of that advisory
//     and package.
//   - All alerts of one key are combined before a rerun is emitted. The key is
//     fixed only when every alert of it is fixed and verifiable. Any open alert is
//     the flaw, and the result is found.
//   - A fixed alert verifies only from a call with state "all" and a list that is
//     not truncated, and only when the alert is verifiable: it has an advisory id
//     and an ecosystem, and its package has one version.
//   - An open alert reopens a fixed Finding even when it is not verifiable: an open
//     alert proves that the flaw is there.
//   - A dismissed alert verifies nothing. It waits for a person, and the result says
//     so. An alert gone from the list verifies nothing either.
//
// The result comes from a server of the buyer, so each field is untrusted. A field
// that fails its check is dropped with a note, and the alert goes on without it.

// DependencyAlertsTool is the name of the connector tool.
const DependencyAlertsTool = "list_dependency_alerts"

// Bounds of the untrusted fields.
const (
	maxAlerts          = 2000
	maxPackageNameLen  = 256
	maxTitleLen        = 200
	maxDescriptionLen  = 2000
	maxPURLLen         = 512
	maxManifestPathLen = 512
)

var (
	ghsaRE = regexp.MustCompile(`^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`)
	cveRE  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	// A purl: pkg:<type>/<name>[@<version>], with a bounded character set.
	purlRE = regexp.MustCompile(`^pkg:([a-z][a-z0-9.+-]{0,31})/[A-Za-z0-9._~%@/+:-]{1,480}$`)
)

// purlTypes are the types of purl that the tool reports.
var purlTypes = map[string]bool{
	"golang": true, "npm": true, "pypi": true, "maven": true, "nuget": true, "gem": true,
	"cargo": true, "composer": true, "hex": true, "pub": true, "swift": true, "cocoapods": true,
	"github": true, "generic": true,
}

var severities = map[string]bool{"low": true, "moderate": true, "medium": true, "high": true, "critical": true, "unknown": true}

// dependencyAlertsResult is the result of list_dependency_alerts. Alerts is a
// pointer: a result with no alerts field is an error, and never an empty list that
// reads as complete.
type dependencyAlertsResult struct {
	Project string `json:"project"`
	// State is the state that the call asked for. Only a call with state "all"
	// can verify a Finding.
	State     string             `json:"state"`
	Truncated bool               `json:"truncated"`
	Alerts    *[]dependencyAlert `json:"alerts"`
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

	// groupPackage is the package name as the tool sent it. It is used to group the
	// alerts of one package and never reaches the graph: a name that fails its check
	// is dropped from Package, and the alert must not move to another group for it.
	groupPackage string
}

// DependencyAlertOutcome is what the mapping made of one result.
type DependencyAlertOutcome struct {
	// Events are the events to submit, in order: the Package entities, then the
	// Findings, then the reruns.
	Events []brain.Event
	// Notes say why an alert verified nothing, or got no Package, or lost a field.
	// The caller logs them. They are for a person.
	Notes []string
}

// advisoryOf returns the advisory id that keys a Finding: the GHSA id, else the
// CVE id, else "". An id that does not match the strict form of its kind is
// ignored.
func advisoryOf(ids []string) string {
	for _, id := range ids {
		if ghsaRE.MatchString(id) {
			return id
		}
	}
	for _, id := range ids {
		if cveRE.MatchString(id) {
			return id
		}
	}
	return ""
}

var dependencyAlertNamespace = uuid.MustParse("3c0b1d7e-5e0a-4f6a-9a53-7a3f2b1c9d10")

// DependencyAlertFindingID returns the identity of the Finding of an alert. It is
// stable across a fix: it holds the repository, the advisory, the ecosystem, the
// package name and the manifest path, and no version. The fields are length
// prefixed (a JSON list), so no value can move text into the next field. An alert
// with no advisory id is keyed on the id of the alert.
func DependencyAlertFindingID(repoKey, advisory, ecosystem, pkg, manifest, alertID string) string {
	fields := []string{"alert", repoKey, advisory, ecosystem, pkg, manifest}
	if advisory == "" {
		fields = []string{"alert-id", repoKey, alertID}
	}
	raw, _ := json.Marshal(fields) // a list of strings always encodes
	return uuid.NewSHA1(dependencyAlertNamespace, raw).String()
}

// RepositoryProject returns the project path of a repository URL, the path after
// the host (owner/repo, or group/subgroup/project). It returns "" for a value that
// RepositoryKey refuses.
func RepositoryProject(rawURL string) string {
	_, path := repositoryParts(rawURL)
	return strings.Trim(strings.TrimSuffix(strings.TrimRight(path, "/"), ".git"), "/")
}

// capText cuts s to at most n bytes at a rune boundary.
func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// cleanAlert checks the untrusted fields of an alert. It returns the alert with
// each failed field dropped, and the notes.
func cleanAlert(a dependencyAlert) (clean dependencyAlert, notes []string) {
	a.groupPackage = capText(strings.TrimSpace(a.Package), maxPackageNameLen*2)
	drop := func(field string) {
		notes = append(notes, fmt.Sprintf("alert %s: the field %s failed its check and was dropped", capText(a.ID, 64), field))
	}
	a.ID = capText(a.ID, 64)
	if len(a.Package) > maxPackageNameLen || strings.ContainsAny(a.Package, "\n\r\x00") {
		drop("package")
		a.Package = ""
	}
	a.Ecosystem = strings.ToLower(strings.TrimSpace(a.Ecosystem))
	if len(a.Ecosystem) > 32 || strings.ContainsAny(a.Ecosystem, " \n\r\x00/") {
		drop("ecosystem")
		a.Ecosystem = ""
	}
	if a.PURL != "" {
		m := purlRE.FindStringSubmatch(a.PURL)
		if len(a.PURL) > maxPURLLen || m == nil || !purlTypes[m[1]] {
			drop("purl")
			a.PURL = ""
		}
	}
	if len(a.ManifestPath) > maxManifestPathLen || strings.ContainsAny(a.ManifestPath, "\n\r\x00") {
		drop("manifest_path")
		a.ManifestPath = ""
	}
	a.Severity = strings.ToLower(strings.TrimSpace(a.Severity))
	if a.Severity != "" && !severities[a.Severity] {
		drop("severity")
		a.Severity = ""
	}
	var ids []string
	for _, id := range a.AdvisoryIDs {
		if ghsaRE.MatchString(id) || cveRE.MatchString(id) {
			ids = append(ids, id)
		} else {
			drop("advisory_ids")
		}
	}
	a.AdvisoryIDs = ids
	a.Version = capText(a.Version, 128)
	a.VulnerableRange = capText(a.VulnerableRange, 256)
	a.FirstPatchedVersion = capText(a.FirstPatchedVersion, 128)
	return a, notes
}

// DependencyAlertEvents maps the result of list_dependency_alerts to events. result
// is the decoded JSON of the tool. repoKey is the key of the Repository of the scan
// (RepositoryKey) and project is the project that the call asked for
// (RepositoryProject). The result must name that project. It returns an error when
// the result is not the shape of the tool.
func DependencyAlertEvents(result any, repoKey, project, missionID, runID string, now time.Time) (DependencyAlertOutcome, error) {
	res, err := parseAlertsResult(result, repoKey, project)
	if err != nil {
		return DependencyAlertOutcome{}, err
	}
	var out DependencyAlertOutcome
	// A truncated list may miss an alert, and a call with another state than "all"
	// does not list the fixed alerts. No alert verifies anything then.
	complete := !res.Truncated && strings.EqualFold(res.State, "all")
	if res.Truncated {
		out.Notes = append(out.Notes, "the list of alerts is truncated, so no alert verifies a finding")
	}
	if !strings.EqualFold(res.State, "all") {
		out.Notes = append(out.Notes, fmt.Sprintf("the call asked for state %q and not \"all\", so no alert verifies a finding", capText(res.State, 32)))
	}

	g := groupAlerts(*res.Alerts, repoKey, &out)
	var packages, raised, reruns []brain.Event
	seenPackage := map[string]bool{}
	for _, id := range g.order {
		k := g.findings[id]
		st := inspectFinding(k, &out)
		if st.open != nil {
			pkgs, pkgEvent := packageOf(*st.open, missionID, runID, seenPackage, &out)
			if pkgEvent != nil {
				packages = append(packages, pkgEvent)
			}
			raised = append(raised, raiseAlert(k, *st.open, repoKey, missionID, runID, now, pkgs))
		}
		if k.advisory == "" {
			continue // a Finding with no advisory id is never verified or reopened by this check
		}
		switch {
		case st.open != nil || anyOpen(g.openByPackage, k.groups):
			// An open alert for this advisory and package, here or in another
			// manifest, proves that the flaw is there. It does not need to be
			// verifiable.
			reruns = append(reruns, brain.CheckRerun{ID: id, CheckKind: string(finding.CheckTool), Found: true, EvidenceAt: now, MissionID: missionID})
		case st.anyFixed && st.allFixed && st.allVerifiable && complete:
			reruns = append(reruns, brain.CheckRerun{ID: id, CheckKind: string(finding.CheckTool), Found: false, EvidenceAt: now, MissionID: missionID})
		}
	}
	sort.Strings(out.Notes)
	out.Notes = dedupeStrings(out.Notes)
	out.Events = append(append(packages, raised...), reruns...)
	return out, nil
}

// parseAlertsResult decodes the result and checks it against the scan.
func parseAlertsResult(result any, repoKey, project string) (dependencyAlertsResult, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return dependencyAlertsResult{}, fmt.Errorf("encode the result of %s: %w", DependencyAlertsTool, err)
	}
	var res dependencyAlertsResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return dependencyAlertsResult{}, fmt.Errorf("the result of %s is not the shape of the tool: %w", DependencyAlertsTool, err)
	}
	switch {
	case res.Alerts == nil:
		return dependencyAlertsResult{}, errors.New("the result has no alerts field, which is not an empty list")
	case repoKey == "" || project == "":
		return dependencyAlertsResult{}, fmt.Errorf("the scan has no Repository, so a Finding of %s has no place", DependencyAlertsTool)
	case !strings.EqualFold(strings.TrimSpace(res.Project), project):
		return dependencyAlertsResult{}, fmt.Errorf("the result names project %q, and the scan asked for %q", res.Project, project)
	case len(*res.Alerts) > maxAlerts:
		return dependencyAlertsResult{}, fmt.Errorf("the result holds %d alerts, more than the %d that the mapping takes", len(*res.Alerts), maxAlerts)
	}
	return res, nil
}

// keyed is the alerts of one Finding.
type keyed struct {
	id       string
	advisory string
	groups   []string
	alerts   []dependencyAlert
}

// grouped is the alerts of a result by the key of their Finding, in first-seen
// order, and the packages that an open alert blocks.
type grouped struct {
	findings      map[string]*keyed
	order         []string
	openByPackage map[string]bool // advisory and package, any manifest
}

// groupAlerts cleans each alert and groups it by the key of its Finding and by
// the advisory and package alone.
func groupAlerts(alerts []dependencyAlert, repoKey string, out *DependencyAlertOutcome) grouped {
	g := grouped{findings: map[string]*keyed{}, openByPackage: map[string]bool{}}
	for _, raw := range alerts {
		a, notes := cleanAlert(raw)
		out.Notes = append(out.Notes, notes...)
		advisory := advisoryOf(a.AdvisoryIDs)
		id := DependencyAlertFindingID(repoKey, advisory, a.Ecosystem, a.Package, a.ManifestPath, a.ID)
		k := g.findings[id]
		if k == nil {
			k = &keyed{id: id, advisory: advisory}
			g.findings[id] = k
			g.order = append(g.order, id)
		}
		k.alerts = append(k.alerts, a)
		k.groups = append(k.groups, packageGroups(a)...)
		k.groups = append(k.groups, packageGroup("*", a))
		if strings.EqualFold(a.State, "open") {
			for _, grp := range packageGroups(a) {
				g.openByPackage[grp] = true
			}
		}
	}
	return g
}

// findingState is what the alerts of one Finding say together.
type findingState struct {
	open                              *dependencyAlert
	allFixed, allVerifiable, anyFixed bool
}

// inspectFinding reads the states of the alerts of one Finding and adds the
// notes for the alerts that verify nothing.
func inspectFinding(k *keyed, out *DependencyAlertOutcome) findingState {
	st := findingState{allFixed: true, allVerifiable: true}
	for i := range k.alerts {
		a := &k.alerts[i]
		switch strings.ToLower(a.State) {
		case "open":
			if st.open == nil {
				st.open = a
			}
			st.allFixed = false
		case "fixed":
			st.anyFixed = true
		default:
			// dismissed, auto_dismissed or a state that this release does not know.
			st.allFixed = false
			out.Notes = append(out.Notes, fmt.Sprintf("alert %s is %s: it verifies nothing and waits for a person", a.ID, capText(a.State, 32)))
		}
		if !verifiable(*a, k.advisory) {
			st.allVerifiable = false
			out.Notes = append(out.Notes, notVerifiableReason(*a, k.advisory))
		}
	}
	return st
}

// packageOf returns the Package list of a Finding and the event that makes the
// Package node, once for each purl.
func packageOf(a dependencyAlert, missionID, runID string, seen map[string]bool, out *DependencyAlertOutcome) ([]string, brain.Event) {
	if a.PURL == "" {
		out.Notes = append(out.Notes, fmt.Sprintf("alert %s has no usable purl, so its Finding has no Package", a.ID))
		return nil, nil
	}
	if seen[a.PURL] {
		return []string{a.PURL}, nil
	}
	seen[a.PURL] = true
	// No properties: an entity sighting copies its properties onto a node that
	// exists, and a Package that trivy wrote must keep its own name and version.
	// The purl holds both.
	return []string{a.PURL}, brain.EntityObserved{Label: "Package", Key: a.PURL, MissionID: missionID, MissionRunID: runID}
}

// raiseAlert is the Finding that an open alert raises.
func raiseAlert(k *keyed, a dependencyAlert, repoKey, missionID, runID string, now time.Time, pkgs []string) brain.Event {
	title := fmt.Sprintf("%s in %s %s", firstNonEmpty(k.advisory, "dependency alert "+a.ID), a.Package, a.Version)
	return brain.FindingRaised{
		ID: k.id, Title: capText(strings.TrimSpace(title), maxTitleLen), Description: capText(alertDescription(a), maxDescriptionLen),
		Severity: a.Severity, ScopeID: missionID, MissionID: missionID, MissionRunID: runID,
		Status: brain.FindingStatusOpen, VulnerabilityID: k.advisory,
		Places:   []brain.FindingPlace{{Label: "Repository", Key: repoKey}},
		Packages: pkgs,
		// The alert is a read of a tool of the buyer. That read verifies the fix.
		CheckKind: string(finding.CheckTool), CheckRef: DependencyAlertsTool,
		At: now,
	}
}

func anyOpen(open map[string]bool, groups []string) bool {
	for _, g := range groups {
		if open[g] {
			return true
		}
	}
	return false
}

// packageGroup is the key of an advisory on a package, in any manifest and in any
// ecosystem. The ecosystem is not part of it: a manifest type that the daemon does
// not know gives an empty ecosystem, and such an open alert must still block.
// The advisory "*" stands for every advisory of the package.
func packageGroup(advisory string, a dependencyAlert) string {
	raw, _ := json.Marshal([]string{advisory, a.groupPackage})
	return string(raw)
}

// packageGroups returns the group of the alert for each of its valid advisory ids
// (GHSA and CVE alike), so an open alert that names the advisory by the other id
// still blocks a verify.
func packageGroups(a dependencyAlert) []string {
	var out []string
	for _, id := range a.AdvisoryIDs {
		out = append(out, packageGroup(id, a))
	}
	if len(out) == 0 {
		// No valid advisory id: the alert blocks every fixed alert of the package
		// (fail safe).
		out = append(out, packageGroup("*", a))
	}
	return out
}

func dedupeStrings(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// verifiable reports whether an alert can verify its Finding: it names an
// advisory and an ecosystem, the tool did not mark it not verifiable, and its
// package has one version.
func verifiable(a dependencyAlert, advisory string) bool {
	if advisory == "" || a.VersionAmbiguous || strings.TrimSpace(a.Ecosystem) == "" || a.Package == "" {
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
