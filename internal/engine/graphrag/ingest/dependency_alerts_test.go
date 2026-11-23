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

const alertRepo = "github.com/acme/shop"

var alertNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func alert(id, state, version string, advisories ...string) map[string]any {
	a := map[string]any{
		"id": id, "state": state, "package": "github.com/acme/lib", "ecosystem": "go",
		"version": version, "advisory_ids": advisories, "severity": "HIGH", "manifest_path": "go.mod",
		"vulnerable_version_range": "< 1.2.3", "first_patched_version": "v1.2.3",
	}
	if version != "" {
		a["purl"] = "pkg:golang/github.com/acme/lib@" + version
	}
	return a
}

func listOf(truncated bool, note string, alerts ...map[string]any) map[string]any {
	as := make([]any, 0, len(alerts))
	for _, a := range alerts {
		as = append(as, a)
	}
	state := "all"
	if note != "" {
		state = note // a call that did not ask for "all"
	}
	return map[string]any{"project": "acme/shop", "state": state, "truncated": truncated, "alerts": as}
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

func TestDependencyAlertEvents_AnOpenAlertRaisesAFindingAtTheRepository(t *testing.T) {
	out, err := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", "open", "v1.2.0", "GHSA-xxxx", "CVE-2026-1")), alertRepo, "m1", "run-1", alertNow)
	require.NoError(t, err)
	raised, reruns, entities := kinds(out.Events)
	require.Len(t, raised, 1)
	f := raised[0]
	assert.Equal(t, "GHSA-xxxx", f.VulnerabilityID, "the advisory key is the GHSA id, else the CVE id")
	assert.Equal(t, "tool", f.CheckKind, "a read of the tool of the buyer raised it")
	assert.Equal(t, []brain.FindingPlace{{Label: "Repository", Key: alertRepo}}, f.Places, "the place is the Repository, never the Package")
	assert.Equal(t, []string{"pkg:golang/github.com/acme/lib@v1.2.0"}, f.Packages)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "m1", f.MissionID)
	require.Len(t, entities, 1)
	assert.Equal(t, "Package", entities[0].Label)
	assert.Equal(t, f.Packages[0], entities[0].Key, "the Package is keyed by the purl, as trivy keys it")
	require.Len(t, reruns, 1)
	assert.True(t, reruns[0].Found, "an open alert says the flaw is there")
}

// The purl holds the version, and a fix changes it. The Finding must have the same
// id before and after, or the rescan sees a new package and never matches.
func TestDependencyAlertEvents_TheFindingIdSurvivesAVersionChange(t *testing.T) {
	a, _ := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", "open", "v1.2.0", "GHSA-xxxx")), alertRepo, "m1", "r", alertNow)
	b, _ := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", "fixed", "v1.2.3", "GHSA-xxxx")), alertRepo, "m2", "r", alertNow)
	ra, _, _ := kinds(a.Events)
	_, rb, _ := kinds(b.Events)
	require.Len(t, ra, 1)
	require.Len(t, rb, 1)
	assert.Equal(t, ra[0].ID, rb[0].ID)
	assert.False(t, rb[0].Found, "a fixed alert on a complete list says the flaw is gone")
	// Another repository, another advisory or another package is another Finding.
	c, _ := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", "open", "v1.2.0", "GHSA-xxxx")), "github.com/acme/other", "m1", "r", alertNow)
	rc, _, _ := kinds(c.Events)
	assert.NotEqual(t, ra[0].ID, rc[0].ID)
}

func TestDependencyAlertEvents_OnlyACompleteListVerifies(t *testing.T) {
	fixed := alert("dependabot:1", "fixed", "v1.2.3", "GHSA-xxxx")
	for name, res := range map[string]map[string]any{
		"truncated":      listOf(true, "", fixed),
		"a tool note":    listOf(false, "the list may be out of date", fixed),
		"dismissed":      listOf(false, "", alert("dependabot:1", "dismissed", "v1.2.0", "GHSA-xxxx")),
		"auto dismissed": listOf(false, "", alert("dependabot:1", "auto_dismissed", "v1.2.0", "GHSA-xxxx")),
		"no advisory id": listOf(false, "", alert("dependabot:1", "fixed", "v1.2.3")),
		"an empty list":  listOf(false, ""),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := DependencyAlertEvents(res, alertRepo, "m1", "r", alertNow)
			require.NoError(t, err)
			_, reruns, _ := kinds(out.Events)
			assert.Empty(t, reruns, "nothing verifies")
			if name != "an empty list" {
				assert.NotEmpty(t, out.Notes, "a person can see why")
			}
		})
	}
	// A dismissed alert says that it waits on a person.
	out, _ := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", "dismissed", "v1.2.0", "GHSA-xxxx")), alertRepo, "m1", "r", alertNow)
	assert.Contains(t, strings.Join(out.Notes, " "), "waits for a person")
}

// An alert with no advisory id raises a Finding and never verifies it. An alert
// with no purl raises a Finding with no Package.
func TestDependencyAlertEvents_MissingFieldsDoNotHideAFinding(t *testing.T) {
	out, err := DependencyAlertEvents(listOf(false, "", alert("dependabot:2", "open", "v1.2.0"), alert("dependabot:3", "open", "", "GHSA-yyyy")), alertRepo, "m1", "r", alertNow)
	require.NoError(t, err)
	raised, reruns, entities := kinds(out.Events)
	require.Len(t, raised, 2)
	assert.Len(t, entities, 1, "only the alert with a purl has a Package")
	for _, f := range raised {
		if f.VulnerabilityID == "GHSA-yyyy" {
			assert.Empty(t, f.Packages, "no purl, no Package")
		}
	}
	require.Len(t, reruns, 1, "the alert with no advisory id has no rerun")
	assert.Contains(t, strings.Join(out.Notes, "\n"), "no purl")
	assert.Contains(t, strings.Join(out.Notes, "\n"), "no advisory id")
}

func TestDependencyAlertEvents_RefusesAResultOfAnotherShapeAndAScanWithNoRepository(t *testing.T) {
	_, err := DependencyAlertEvents(map[string]any{"alerts": "not a list"}, alertRepo, "m1", "r", alertNow)
	require.Error(t, err)
	_, err = DependencyAlertEvents(listOf(false, ""), "", "m1", "r", alertNow)
	require.Error(t, err)
}

// The whole loop in a World: an open alert raises the Finding, the fix is merged
// and deployed, and a later scan reads the alert as fixed. The Finding verifies.
// A scan that reads the alert as dismissed leaves it fixed.
func TestDependencyAlertEvents_AFixedAlertVerifiesTheFinding(t *testing.T) {
	for state, want := range map[string]string{"fixed": brain.FindingStatusVerified, "dismissed": brain.FindingStatusFixed} {
		w := brain.NewWorld("acme")
		raise, _ := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", "open", "v1.2.0", "GHSA-xxxx")), alertRepo, "scan-1", "run-1", alertNow.Add(-2*time.Hour))
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

		rescan, _ := DependencyAlertEvents(listOf(false, "", alert("dependabot:1", state, "v1.2.3", "GHSA-xxxx")), alertRepo, "scan-2", "run-2", alertNow)
		for _, e := range rescan.Events {
			brain.Reduce(w, e)
		}
		for _, e := range brain.VerificationSystem(w) {
			brain.Reduce(w, e)
		}
		assert.Equal(t, want, w.FindingSnapshot()[0].Status, "alert state %s", state)
	}
}

// An alert for a package at several versions has no version and no purl. It raises
// a Finding and never verifies or reopens it.
func TestDependencyAlertEvents_AnAmbiguousVersionNeverVerifies(t *testing.T) {
	amb := alert("dependabot:9", "fixed", "", "GHSA-zzzz")
	amb["version_ambiguous"] = true
	amb["versions"] = []any{"v1.0.0", "v1.1.0"}
	open := alert("dependabot:10", "open", "", "GHSA-zzzz")
	open["version_ambiguous"] = true
	open["versions"] = []any{"v1.0.0", "v1.1.0"}
	out, err := DependencyAlertEvents(listOf(false, "", amb, open), alertRepo, "m1", "r", alertNow)
	require.NoError(t, err)
	raised, reruns, entities := kinds(out.Events)
	assert.Len(t, raised, 1, "the open alert raises a Finding")
	assert.Empty(t, reruns)
	assert.Empty(t, entities, "no purl, no Package")
	assert.Contains(t, strings.Join(out.Notes, "\n"), "several versions")

	notVerifiable := alert("dependabot:11", "fixed", "v1.2.3", "GHSA-xxxx")
	notVerifiable["verifiable"] = false
	out, _ = DependencyAlertEvents(listOf(false, "", notVerifiable), alertRepo, "m1", "r", alertNow)
	_, reruns, _ = kinds(out.Events)
	assert.Empty(t, reruns, "the tool marked the alert not verifiable")
}
