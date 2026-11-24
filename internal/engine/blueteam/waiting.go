// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"fmt"
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
	// WaitNoFixHead is a finding in `fixing` whose link recorded no head for the
	// fix. The fix agent makes no merge call without a head, so a person looks at
	// the merge request. The reason says why the daemon recorded none.
	WaitNoFixHead WaitKind = "no_fix_head"
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
	// WaitHoldUnreadable is a `fixed` finding whose hold time the daemon could not
	// read from the fix mission at the deploy.
	WaitHoldUnreadable WaitKind = brain.WaitHoldUnreadable
	// WaitRevertPending is a `fixed` finding whose health signal failed and whose
	// revert merge request is not merged yet. Its slot blocks the Application
	// until the revert merges (gibson#1609).
	WaitRevertPending WaitKind = brain.WaitRevertPending
	// WaitNoSingleApplication is a finding that reaches no Application or more than
	// one, so the fix loop gives it no merge slot. The reason is the text of
	// Finding.PlaceBlock. The wait ends when the finding again reaches one
	// Application (gibson#1469).
	WaitNoSingleApplication WaitKind = "no_single_application"
	// WaitRevertFailed is the same finding when the revert call failed.
	WaitRevertFailed WaitKind = brain.WaitRevertFailed
	// WaitFixAttemptsFailed is an open finding with brain.MaxFixAttempts failed fix
	// jobs in a row. The finding takes no new fix job until a person acts
	// (gibson#1674).
	WaitFixAttemptsFailed WaitKind = "fix_attempts_failed"
	// WaitMergeCloseFailed is a finding whose failed fix job left a merge request
	// that the daemon could not close. The reason names the merge request
	// (gibson#1674).
	WaitMergeCloseFailed WaitKind = "merge_request_close_failed"
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
var WaitingKinds = []string{
	brain.MergeRequestObserved{}.Kind(), brain.FixWaiting{}.Kind(), brain.FindingStatusChanged{}.Kind(),
	brain.FindingPlaceBlocked{}.Kind(),
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
	linked := linkTimes(history)
	placed := placeBlockTimes(history)
	for _, f := range findings {
		if f.PlaceBlock != "" && f.Status != brain.FindingStatusVerified {
			// A finding with a place block always shows the wait. When the history
			// read no longer holds the event, the wait starts at the last known time
			// of the finding, else now: short history never hides it.
			since := placed[f.ID]
			if since.IsZero() {
				since = lastKnown(f, linked[f.ID], now)
			}
			add(WaitNoSingleApplication, f.ID, since, f.PlaceBlock)
		}
		if f.Status == brain.FindingStatusOpen && f.FixAttemptsBlocked() {
			add(WaitFixAttemptsFailed, f.ID, f.FixBlockedAt, fixAttemptsReason(f))
		}
		if w := f.FixCloseWait; w.JobID != "" {
			add(WaitMergeCloseFailed, f.ID, w.Since, fmt.Sprintf(
				"merge request %s of the failed job %s is still open: %s", w.MergeRequest, w.JobID, w.Reason))
		}
		switch f.Status {
		case brain.FindingStatusFixing:
			r := refusals[f.MergeRequest]
			add(WaitMergeRefused, f.ID, r.at, r.reason)
			// A linked fix with no head waits on a person, with or without a recorded
			// reason. The daemon can stop between the link events and the head events,
			// and a finding from before FixHeadMissing has no reason.
			if f.FixHeadSHA == "" && f.MergeRequest != "" {
				since, reason := f.FixHeadMissingAt, f.FixHeadMissingReason
				if reason == "" {
					reason = "no fix head was recorded"
					// The time of the link: the history, then the time that the finding
					// holds for its merge request, then the claim, then now. A history
					// that was trimmed and a finding from before LinkedAt must still show
					// the wait, so the chain ends at now.
					for _, t := range []time.Time{linked[f.ID], f.LinkedAt, f.FixClaimedAt, now} {
						if since = t; !since.IsZero() {
							break
						}
					}
				}
				add(WaitNoFixHead, f.ID, since, reason)
			}
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
				h := waits[waitKey{f.MergeRequest, brain.WaitHoldUnreadable}]
				add(WaitHoldUnreadable, f.ID, h.at, h.reason)
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

// fixAttemptsReason says how many fix jobs failed in a row and why the last one
// failed.
func fixAttemptsReason(f brain.FindingSnapshot) string {
	n := len(f.FixAttempts)
	reason := fmt.Sprintf("%d fix jobs failed in a row.", n)
	if n == 0 {
		return reason
	}
	last := f.FixAttempts[n-1]
	return fmt.Sprintf("%s The last is job %s: %s", reason, last.JobID, last.Reason)
}

func rerunAfterDeploy(f brain.FindingSnapshot) bool {
	return !f.RerunAt.IsZero() && f.RerunAt.After(f.DeployedAt)
}

// lastKnown is the latest time that the snapshot of a finding records, else now.
func lastKnown(f brain.FindingSnapshot, linked, now time.Time) time.Time {
	best := time.Time{}
	for _, t := range []time.Time{
		f.RaisedAt, f.FirstSeenAt, f.FixClaimedAt, f.FixHeadMissingAt, f.DeployedAt,
		f.HealthUnavailableAt, f.RerunAt, f.RevertRequestedAt, linked,
	} {
		if t.After(best) {
			best = t
		}
	}
	if best.IsZero() {
		return now
	}
	return best
}

// placeBlockTimes returns, for each finding, the time of the event that set its
// place block. An event with an empty reason ends the wait.
func placeBlockTimes(history []brain.Event) map[string]time.Time {
	out := map[string]time.Time{}
	for _, raw := range history {
		var e brain.FindingPlaceBlocked
		switch v := raw.(type) {
		case brain.FindingPlaceBlocked:
			e = v
		case *brain.FindingPlaceBlocked:
			e = *v
		default:
			continue
		}
		if e.Reason == "" {
			delete(out, e.ID)
			continue
		}
		out[e.ID] = e.At
	}
	return out
}

// linkTimes returns, for each finding, the time of its last status change to fixing
// with a merge request: the time of the link.
func linkTimes(history []brain.Event) map[string]time.Time {
	out := map[string]time.Time{}
	for _, raw := range history {
		var e brain.FindingStatusChanged
		switch v := raw.(type) {
		case brain.FindingStatusChanged:
			e = v
		case *brain.FindingStatusChanged:
			e = *v
		default:
			continue
		}
		if e.Status == brain.FindingStatusFixing && e.MergeRequest != "" {
			out[e.ID] = e.At
		}
	}
	return out
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
