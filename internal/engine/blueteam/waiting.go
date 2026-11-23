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
	// WaitMergeUnreadable is a finding in `fixing` whose merge request the
	// daemon cannot read on the Git host. Its slot stays (gibson#1609).
	WaitMergeUnreadable WaitKind = brain.WaitMergeUnreadable
	// WaitNoHealthVerdict is a `fixed` finding with no health verdict after the
	// grant window of its merge slot (gibson#1609, gibson#1463).
	WaitNoHealthVerdict WaitKind = brain.WaitNoHealthVerdict
	// WaitRevertPending is a `fixed` finding whose health signal failed and whose
	// revert merge request is not merged yet. Its slot blocks the Application
	// until the revert merges (gibson#1609).
	WaitRevertPending WaitKind = brain.WaitRevertPending
	// WaitRevertFailed is the same finding when the revert call failed.
	WaitRevertFailed WaitKind = brain.WaitRevertFailed
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
	// Reason says why the item waits, when the Timeline records a reason. For a
	// refused merge it is what the Git host said.
	Reason string
}

// WaitingKinds are the kinds of the history events that WaitingOnPerson reads.
var WaitingKinds = []string{brain.MergeRequestObserved{}.Kind(), brain.FixWaiting{}.Kind()}

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
	add := func(k WaitKind, id string, since time.Time, reason string) {
		if since.IsZero() {
			return
		}
		out = append(out, WaitItem{Kind: k, ID: id, Since: since.UTC(), Waited: max(0, now.Sub(since)), Reason: reason})
	}
	for _, a := range actions {
		if !a.Decided {
			add(WaitDestructiveAction, a.HypothesisID, time.UnixMilli(a.RequestedAtUnixMS), "")
		}
	}
	refusals := lastRefusals(history)
	waits := lastWaits(history)
	for _, f := range findings {
		switch f.Status {
		case brain.FindingStatusFixing:
			r := refusals[f.MergeRequest]
			add(WaitMergeRefused, f.ID, r.at, r.reason)
			u := waits[waitKey{f.MergeRequest, brain.WaitMergeUnreadable}]
			add(WaitMergeUnreadable, f.ID, u.at, u.reason)
		case brain.FindingStatusFixed:
			if f.CheckKind == string(finding.CheckTool) && !f.DeployedAt.IsZero() && !rerunAfterDeploy(f) {
				add(WaitNextScan, f.ID, f.DeployedAt, "")
			}
			add(WaitNoHealthSignal, f.ID, f.HealthUnavailableAt, "")
			switch f.Health {
			case "":
				v := waits[waitKey{f.MergeRequest, brain.WaitNoHealthVerdict}]
				add(WaitNoHealthVerdict, f.ID, v.at, v.reason)
			case brain.HealthFailed:
				p := waits[waitKey{f.MergeRequest, brain.WaitRevertPending}]
				add(WaitRevertPending, f.ID, p.at, p.reason)
				r := waits[waitKey{f.MergeRequest, brain.WaitRevertFailed}]
				add(WaitRevertFailed, f.ID, r.at, r.reason)
			}
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

// waitStart is the start of a wait and what the Timeline says about it.
type waitStart struct {
	at     time.Time
	reason string
}

// lastRefusals returns, for each merge request, the time and the reason of its
// refusal when the refusal is the last report about it. A later report ends the
// wait.
func lastRefusals(history []brain.Event) map[string]waitStart {
	out := map[string]waitStart{}
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
				out[e.Key] = waitStart{at: e.At, reason: e.Reason} // the wait starts at the first refusal
			}
			continue
		}
		delete(out, e.Key)
	}
	return out
}

type waitKey struct{ mergeRequest, kind string }

// lastWaits returns, for each merge request and kind, the start of the wait when
// the last FixWaiting event of that kind says that it waits. A later event that
// says it does not ends the wait.
func lastWaits(history []brain.Event) map[waitKey]waitStart {
	out := map[waitKey]waitStart{}
	for _, raw := range history {
		var e brain.FixWaiting
		switch v := raw.(type) {
		case brain.FixWaiting:
			e = v
		case *brain.FixWaiting:
			e = *v
		default:
			continue
		}
		k := waitKey{e.MergeRequest, e.WaitKind}
		if !e.Waiting {
			delete(out, k)
			continue
		}
		if _, open := out[k]; !open {
			out[k] = waitStart{at: e.At, reason: e.Reason}
		}
	}
	return out
}
