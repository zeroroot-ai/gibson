// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"sort"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// WaitKind names why an item waits on a person.
type WaitKind string

// The four kinds of item (gibson#1500).
const (
	// WaitDestructiveAction is a destructive action with no decision.
	WaitDestructiveAction WaitKind = "destructive_action"
	// WaitMergeRefused is a finding in `fixing` whose merge the branch
	// protection refused.
	WaitMergeRefused WaitKind = "merge_refused"
	// WaitNextScan is a `fixed` finding that waits on the next scan of a tool
	// of the buyer.
	WaitNextScan WaitKind = "next_scan"
	// WaitNoHealthSignal is a `fixed` finding of a service with no health
	// signal.
	WaitNoHealthSignal WaitKind = "no_health_signal"
)

// WaitItem is one item that waits on a person.
type WaitItem struct {
	Kind WaitKind
	// ID is the id of the finding, or the id of the hypothesis for a
	// destructive action.
	ID    string
	Since time.Time
	// Waited is the time from Since to now.
	Waited time.Duration
}

// WaitingOnPerson returns each item that waits on a person, the longest wait
// first. history is the durable Timeline of the tenant. The in-memory Timeline
// holds only the tail after a snapshot and cannot give the time of a refusal.
func WaitingOnPerson(
	findings []brain.FindingSnapshot,
	actions []brain.DestructiveActionSnapshot,
	history []brain.Event,
	now time.Time,
) []WaitItem {
	var out []WaitItem
	add := func(k WaitKind, id string, since time.Time) {
		if since.IsZero() {
			return
		}
		out = append(out, WaitItem{Kind: k, ID: id, Since: since.UTC(), Waited: max(0, now.Sub(since))})
	}
	for _, a := range actions {
		if !a.Decided {
			add(WaitDestructiveAction, a.HypothesisID, time.UnixMilli(a.RequestedAtUnixMS))
		}
	}
	refusedAt := lastRefusals(history)
	for _, f := range findings {
		switch f.Status {
		case brain.FindingStatusFixing:
			add(WaitMergeRefused, f.ID, refusedAt[f.MergeRequest])
		case brain.FindingStatusFixed:
			if f.CheckKind == string(finding.CheckTool) && !f.DeployedAt.IsZero() && !rerunAfterDeploy(f) {
				add(WaitNextScan, f.ID, f.DeployedAt)
			}
			add(WaitNoHealthSignal, f.ID, f.HealthUnavailableAt)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Waited != out[j].Waited {
			return out[i].Waited > out[j].Waited
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func rerunAfterDeploy(f brain.FindingSnapshot) bool {
	return !f.RerunAt.IsZero() && f.RerunAt.After(f.DeployedAt)
}

// lastRefusals returns, for each merge request, the time of its refusal when
// the refusal is the last report about it. A later report ends the wait.
func lastRefusals(history []brain.Event) map[string]time.Time {
	out := map[string]time.Time{}
	for _, raw := range history {
		var e brain.MergeRequestObserved
		switch v := raw.(type) {
		case brain.MergeRequestObserved:
			e = v
		case *brain.MergeRequestObserved:
			e = *v
		default:
			continue
		}
		if e.State == brain.MergeRequestRefused {
			if _, open := out[e.Key]; !open {
				out[e.Key] = e.At // the wait starts at the first refusal
			}
			continue
		}
		delete(out, e.Key)
	}
	return out
}
