// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

const (
	alertRepo    = "github.com/acme/shop"
	alertProject = "acme/shop"
	ghsaX        = "GHSA-2222-3333-4444"
	ghsaY        = "GHSA-5555-6666-7777"
)

var alertNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func alert(id, state, version string, advisories ...string) map[string]any {
	a := map[string]any{
		"id": id, "state": state, "package": "github.com/acme/lib", "ecosystem": "go",
		"version": version, "advisory_ids": advisories, "severity": "high", "manifest_path": "go.mod",
		"vulnerable_version_range": "< 1.2.3", "first_patched_version": "v1.2.3",
	}
	if version != "" {
		a["purl"] = "pkg:golang/github.com/acme/lib@" + version
	}
	return a
}

func inManifest(a map[string]any, path string) map[string]any {
	a["manifest_path"] = path
	return a
}

// listOf builds a result. state is the state that the call asked for: "all" for a
// complete list.
func listOf(truncated bool, state string, alerts ...map[string]any) map[string]any {
	as := make([]any, 0, len(alerts))
	for _, a := range alerts {
		as = append(as, a)
	}
	return map[string]any{"project": alertProject, "state": state, "truncated": truncated, "alerts": as}
}

func complete(alerts ...map[string]any) map[string]any { return listOf(false, "all", alerts...) }

func run(t *testing.T, res map[string]any, mission string) DependencyAlertOutcome {
	t.Helper()
	out, err := DependencyAlertEvents(res, alertRepo, alertProject, mission, "r", alertNow)
	require.NoError(t, err)
	return out
}

func kinds(evs []brain.Event) (raised []brain.FindingRaised, reruns []brain.CheckRerun, entities []brain.EntityObserved) {
	for _, e := range evs {
		switch v := e.(type) {
		case brain.FindingRaised:
			raised = append(raised, v)
		case brain.CheckRerun:
			reruns = append(reruns, v)
		case brain.EntityObserved:
			entities = append(entities, v)
		}
	}
	return
}

func rerunByID(reruns []brain.CheckRerun) map[string]bool {
	m := map[string]bool{}
	for _, r := range reruns {
		m[r.ID] = r.Found
	}
	return m
}

func TestDependencyAlertEvents_AnOpenAlertRaisesAFindingAtTheRepository(t *testing.T) {
	out := run(t, complete(alert("dependabot:1", "open", "v1.2.0", ghsaX, "CVE-2026-1234")), "m1")
	raised, reruns, entities := kinds(out.Events)
	require.Len(t, raised, 1)
	f := raised[0]
	assert.Equal(t, ghsaX, f.VulnerabilityID, "the advisory key is the GHSA id, else the CVE id")
	assert.Equal(t, "tool", f.CheckKind)
	assert.Equal(t, []brain.FindingPlace{{Label: "Repository", Key: alertRepo}}, f.Places, "the place is the Repository, never the Package")
	assert.Equal(t, []string{"pkg:golang/github.com/acme/lib@v1.2.0"}, f.Packages)
	assert.Equal(t, "high", f.Severity)
	require.Len(t, entities, 1)
	assert.Equal(t, f.Packages[0], entities[0].Key, "the Package is keyed by the purl, as trivy keys it")
	assert.Empty(t, entities[0].Props, "no properties: a Package that trivy wrote keeps its own name and version")
	require.Len(t, reruns, 1)
	assert.True(t, reruns[0].Found)
}

// The purl holds the version, and a fix changes it. The Finding must have the same
// id before and after.
func TestDependencyAlertEvents_TheFindingIdSurvivesAVersionChange(t *testing.T) {
	a := run(t, complete(alert("dependabot:1", "open", "v1.2.0", ghsaX)), "m1")
	b := run(t, complete(alert("dependabot:1", "fixed", "v1.2.3", ghsaX)), "m2")
	ra, _, _ := kinds(a.Events)
	_, rb, _ := kinds(b.Events)
	require.Len(t, rb, 1)
	assert.Equal(t, ra[0].ID, rb[0].ID)
	assert.False(t, rb[0].Found, "a fixed alert on a complete list says the flaw is gone")
	c, err := DependencyAlertEvents(complete(alert("dependabot:1", "open", "v1.2.0", ghsaX)), "github.com/acme/other", alertProject, "m1", "r", alertNow)
	require.NoError(t, err)
	rc, _, _ := kinds(c.Events)
	assert.NotEqual(t, ra[0].ID, rc[0].ID, "another repository is another Finding")
}

// The fields of the key cannot move text into the next field.
func TestDependencyAlertFindingID_FieldsDoNotRunTogether(t *testing.T) {
	a := DependencyAlertFindingID("r", "GHSA-a", "go|x", "pkg", "go.mod", "1")
	b := DependencyAlertFindingID("r", "GHSA-a", "go", "x|pkg", "go.mod", "1")
	assert.NotEqual(t, a, b)
}

func TestDependencyAlertEvents_OnlyACompleteListVerifies(t *testing.T) {
	fixed := alert("dependabot:1", "fixed", "v1.2.3", ghsaX)
	for name, res := range map[string]map[string]any{
		"truncated":                       listOf(true, "all", fixed),
		"a call that did not ask for all": listOf(false, "open", fixed),
		"dismissed":                       complete(alert("dependabot:1", "dismissed", "v1.2.0", ghsaX)),
		"auto dismissed":                  complete(alert("dependabot:1", "auto_dismissed", "v1.2.0", ghsaX)),
		"no advisory id":                  complete(alert("dependabot:1", "fixed", "v1.2.3")),
		"an empty list":                   complete(),
	} {
		t.Run(name, func(t *testing.T) {
			out := run(t, res, "m1")
			_, reruns, _ := kinds(out.Events)
			assert.Empty(t, reruns, "nothing verifies")
			if name != "an empty list" {
				assert.NotEmpty(t, out.Notes, "a person can see why")
			}
		})
	}
	out := run(t, complete(alert("dependabot:1", "dismissed", "v1.2.0", ghsaX)), "m1")
	assert.Contains(t, strings.Join(out.Notes, " "), "waits for a person")
}

// Two alerts with one key (one version resolved, another still detected) must give
// one answer: the flaw is there. The order of the list must not decide.
func TestDependencyAlertEvents_AlertsOfOneKeyAreCombined(t *testing.T) {
	resolved := alert("dependabot:1", "fixed", "v1.1.0", ghsaX)
	detected := alert("dependabot:2", "open", "v1.0.0", ghsaX)
	for name, res := range map[string]map[string]any{
		"fixed first": complete(resolved, detected),
		"open first":  complete(detected, resolved),
	} {
		t.Run(name, func(t *testing.T) {
			out := run(t, res, "m1")
			raised, reruns, _ := kinds(out.Events)
			require.Len(t, raised, 1, "one key is one Finding")
			require.Len(t, reruns, 1)
			assert.True(t, reruns[0].Found, "one open alert of the key is the flaw")
		})
	}
	both := run(t, complete(alert("dependabot:1", "fixed", "v1.1.0", ghsaX), alert("dependabot:2", "fixed", "v1.0.0", ghsaX)), "m1")
	_, reruns, _ := kinds(both.Events)
	require.Len(t, reruns, 1)
	assert.False(t, reruns[0].Found, "every alert of the key is fixed")
}

// An open alert proves that the flaw is there, also when it is not verifiable or its
// package has more than one version.
func TestDependencyAlertEvents_AnOpenAlertAlwaysReopens(t *testing.T) {
	amb := alert("dependabot:9", "open", "", ghsaX)
	amb["version_ambiguous"] = true
	amb["versions"] = []any{"v1.0.0", "v1.1.0"}
	noEco := alert("dependabot:8", "open", "v1.0.0", ghsaY)
	noEco["ecosystem"] = ""
	notVerifiable := alert("dependabot:7", "open", "v1.0.0", "CVE-2026-9999")
	notVerifiable["verifiable"] = false
	out := run(t, complete(amb, noEco, notVerifiable), "m1")
	raised, reruns, _ := kinds(out.Events)
	assert.Len(t, raised, 3)
	require.Len(t, reruns, 3)
	for _, r := range reruns {
		assert.True(t, r.Found)
	}
}

// One advisory can name a package in two manifests. They are two Findings, and the
// fix of one does not verify the other. A fix that moves the package to a new
// manifest (the old alert fixed, a new one open) does not verify either.
func TestDependencyAlertEvents_TheManifestKeysTheFindingButAnyOpenAlertOfThePackageBlocksVerify(t *testing.T) {
	web := inManifest(alert("dependabot:1", "open", "v1.2.0", ghsaX), "web/package-lock.json")
	api := inManifest(alert("dependabot:2", "open", "v1.2.0", ghsaX), "api/package-lock.json")
	two := run(t, complete(web, api), "m1")
	raised, _, _ := kinds(two.Events)
	require.Len(t, raised, 2)
	assert.NotEqual(t, raised[0].ID, raised[1].ID)
	ids := map[string]string{} // manifest -> id
	for _, f := range raised {
		if strings.Contains(f.Description, "web/") {
			ids["web"] = f.ID
		} else {
			ids["api"] = f.ID
		}
	}

	// The web manifest is fixed, the api manifest is still open: the web Finding
	// is reopened by the open alert of the api manifest, and does not verify.
	webFixed := inManifest(alert("dependabot:1", "fixed", "v1.2.3", ghsaX), "web/package-lock.json")
	out := run(t, complete(webFixed, api), "m2")
	_, reruns, _ := kinds(out.Events)
	got := rerunByID(reruns)
	assert.True(t, got[ids["web"]], "an open alert in another manifest reopens the fixed Finding")
	assert.True(t, got[ids["api"]])

	// Both fixed: both verify.
	apiFixed := inManifest(alert("dependabot:2", "fixed", "v1.2.3", ghsaX), "api/package-lock.json")
	out = run(t, complete(webFixed, apiFixed), "m3")
	_, reruns, _ = kinds(out.Events)
	got = rerunByID(reruns)
	assert.False(t, got[ids["web"]])
	assert.False(t, got[ids["api"]])

	// The package moved from package-lock.json to yarn.lock: the old alert is fixed
	// and a new alert opens under the new path. The old Finding must not verify.
	moved := inManifest(alert("dependabot:5", "open", "v1.2.0", ghsaX), "web/yarn.lock")
	out = run(t, complete(webFixed, moved), "m4")
	_, reruns, _ = kinds(out.Events)
	assert.True(t, rerunByID(reruns)[ids["web"]], "a move to another manifest is not a fix")
}

// An alert for another package or another advisory in the open set does not block.
func TestDependencyAlertEvents_AnotherPackageDoesNotBlockTheVerify(t *testing.T) {
	fixed := alert("dependabot:1", "fixed", "v1.2.3", ghsaX)
	other := alert("dependabot:2", "open", "v1.0.0", ghsaY)
	out := run(t, complete(fixed, other), "m1")
	raised, reruns, _ := kinds(out.Events)
	require.Len(t, raised, 1)
	assert.Len(t, reruns, 2)
	for _, r := range reruns {
		if r.ID != raised[0].ID {
			assert.False(t, r.Found)
		}
	}
}

func TestDependencyAlertEvents_AnAmbiguousVersionOrNoEcosystemNeverVerifies(t *testing.T) {
	amb := alert("dependabot:9", "fixed", "", ghsaX)
	amb["version_ambiguous"] = true
	amb["versions"] = []any{"v1.0.0", "v1.1.0"}
	noEco := alert("dependabot:5", "fixed", "v1.2.3", ghsaY)
	noEco["ecosystem"] = ""
	notVerifiable := alert("dependabot:11", "fixed", "v1.2.3", "CVE-2026-9999")
	notVerifiable["verifiable"] = false
	out := run(t, complete(amb, noEco, notVerifiable), "m1")
	_, reruns, _ := kinds(out.Events)
	assert.Empty(t, reruns)
	notes := strings.Join(out.Notes, "\n")
	assert.Contains(t, notes, "several versions")
	assert.Contains(t, notes, "no ecosystem")
}

func TestDependencyAlertEvents_MissingFieldsDoNotHideAFinding(t *testing.T) {
	out := run(t, complete(alert("dependabot:2", "open", "v1.2.0"), alert("dependabot:3", "open", "", ghsaY)), "m1")
	raised, reruns, entities := kinds(out.Events)
	require.Len(t, raised, 2)
	assert.Len(t, entities, 1, "only the alert with a purl has a Package")
	require.Len(t, reruns, 1, "the alert with no advisory id has no rerun")
	assert.Contains(t, strings.Join(out.Notes, "\n"), "no usable purl")
}

// A result of another shape, a project that is not the one asked for, no alerts
// field and a scan with no Repository are errors.
func TestDependencyAlertEvents_RefusesWhatItCannotTrust(t *testing.T) {
	_, err := DependencyAlertEvents(map[string]any{"alerts": "not a list"}, alertRepo, alertProject, "m", "r", alertNow)
	require.Error(t, err)
	_, err = DependencyAlertEvents(map[string]any{"project": alertProject, "state": "all"}, alertRepo, alertProject, "m", "r", alertNow)
	require.Error(t, err, "no alerts field is not an empty complete list")
	assert.Contains(t, err.Error(), "no alerts field")
	_, err = DependencyAlertEvents(complete(), "", "", "m", "r", alertNow)
	require.Error(t, err)
	wrong := complete(alert("dependabot:1", "fixed", "v1.2.3", ghsaX))
	wrong["project"] = "acme/other"
	_, err = DependencyAlertEvents(wrong, alertRepo, alertProject, "m", "r", alertNow)
	require.Error(t, err, "a result for another project must not verify this one")
	// An empty list that the tool sent is complete: it has the field.
	_, err = DependencyAlertEvents(complete(), alertRepo, alertProject, "m", "r", alertNow)
	require.NoError(t, err)
}

// The fields come from a server of the buyer. A field that fails its check is
// dropped, with a note, and the alert goes on.
func TestDependencyAlertEvents_DropsAFieldThatFailsItsCheck(t *testing.T) {
	a := alert("dependabot:1", "open", "v1.2.0", ghsaX, "GHSA-not-valid", "CVE-12-3")
	a["purl"] = "pkg:weird/not a purl\nwith a newline"
	a["severity"] = "catastrophic"
	a["package"] = strings.Repeat("x", 300)
	out := run(t, complete(a), "m1")
	raised, _, entities := kinds(out.Events)
	require.Len(t, raised, 1, "the alert still raises its Finding")
	assert.Equal(t, ghsaX, raised[0].VulnerabilityID, "the valid advisory id is kept")
	assert.Empty(t, raised[0].Packages, "a purl that fails its check is dropped")
	assert.Empty(t, entities)
	assert.Empty(t, raised[0].Severity)
	notes := strings.Join(out.Notes, "\n")
	for _, f := range []string{"purl", "severity", "package", "advisory_ids"} {
		assert.Contains(t, notes, "the field "+f+" failed its check")
	}

	long := alert("dependabot:2", "open", "v1.2.0", ghsaY)
	long["vulnerable_version_range"] = strings.Repeat("é", 5000)
	out = run(t, complete(long), "m1")
	raised, _, _ = kinds(out.Events)
	require.Len(t, raised, 1)
	assert.LessOrEqual(t, len(raised[0].Description), maxDescriptionLen)
	assert.LessOrEqual(t, len(raised[0].Title), maxTitleLen)
	assert.True(t, strings.ToValidUTF8(raised[0].Description, "") == raised[0].Description, "a cut keeps the text valid UTF-8")

	for _, bad := range []string{"GHSA-2222-3333", "GHSA-2222-3333-44445", "ghsa-2222-3333-4444 ", "CVE-2026-1", "CVE-2026-1234; drop"} {
		assert.Empty(t, advisoryOf([]string{bad}), bad)
	}
	assert.Equal(t, "CVE-2026-12345", advisoryOf([]string{"CVE-2026-12345"}))
}

// The whole loop in a World: an open alert raises the Finding, the fix is merged
// and deployed, and a later fixed alert verifies it. A dismissed alert leaves it
// fixed.
func TestDependencyAlertEvents_AFixedAlertVerifiesTheFinding(t *testing.T) {
	for state, want := range map[string]string{"fixed": brain.FindingStatusVerified, "dismissed": brain.FindingStatusFixed} {
		w := brain.NewWorld("acme")
		raise, err := DependencyAlertEvents(complete(alert("dependabot:1", "open", "v1.2.0", ghsaX)), alertRepo, alertProject, "scan-1", "run-1", alertNow.Add(-2*time.Hour))
		require.NoError(t, err)
		for _, e := range raise.Events {
			brain.Reduce(w, e)
		}
		id := w.FindingSnapshot()[0].ID
		for _, s := range []string{brain.FindingStatusFixing, brain.FindingStatusFixed} {
			ev := brain.FindingStatusChanged{ID: id, Status: s}
			if s == brain.FindingStatusFixing {
				ev.MergeRequest = "mr-1"
			}
			brain.Reduce(w, ev)
		}
		brain.Reduce(w, brain.DeployObserved{MergeRequest: "mr-1", At: alertNow.Add(-time.Hour)})
		brain.Reduce(w, brain.HealthObserved{MergeRequest: "mr-1", Held: true, At: alertNow.Add(-time.Hour)})

		rescan, err := DependencyAlertEvents(complete(alert("dependabot:1", state, "v1.2.3", ghsaX)), alertRepo, alertProject, "scan-2", "run-2", alertNow)
		require.NoError(t, err)
		for _, e := range rescan.Events {
			brain.Reduce(w, e)
		}
		for _, e := range brain.VerificationSystem(w) {
			brain.Reduce(w, e)
		}
		assert.Equal(t, want, w.FindingSnapshot()[0].Status, "alert state %s", state)
	}
}

// The project of a repository URL is the path after the host, as the anchors parse it.
func TestRepositoryProject(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/acme/shop.git":       "acme/shop",
		"git@gitlab.com:group/sub/project.git":   "group/sub/project",
		"https://git.example.com:8443/Team/Api/": "Team/Api",
		"not a url":                              "",
	} {
		assert.Equal(t, want, RepositoryProject(in), in)
	}
}
