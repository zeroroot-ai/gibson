// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"
	"time"
)

// exposure.go computes the exposure window of a Finding and the revert rate of
// a tenant from Timeline events (gibson#1467, #1468).
//
// Both are read functions. They fold events and nothing else, and they read time
// only from the events, so a replay of the Timeline gives the same numbers. The
// caller passes the whole Timeline of the tenant. The in-memory Timeline of an
// Engine holds only the tail after the last snapshot, so a caller that needs the
// full history loads it from the durable store.
//
// The exposure window of a Finding runs from its first evidence to the event
// that sets `verified`. It has two parts. Wait time is the time in which no
// agent works and the fix waits on a person or on a tool of the buyer. Agent
// time is the rest. Wait time holds three kinds of time:
//
//   - the time from the first sight of the flaw by the tool of the buyer to the
//     read by Gibson,
//   - the time of a refused merge, until the next report of that merge request,
//   - the time from the deploy to the first rerun of the check on newer
//     evidence, which is the wait for the buyer's next scan,
//   - the time from the request of a revert to the merge of the revert, which
//     is the wait for the pipeline of the buyer. The flaw stays exposed.

// ExposureWindow is the window of one Finding.
type ExposureWindow struct {
	FindingID string
	Start     time.Time
	// End is the time of the `verified` event, or the time of the read for a
	// Finding that is not verified.
	End      time.Time
	Verified bool
	Total    time.Duration
	Wait     time.Duration
	Agent    time.Duration
}

type interval struct{ from, to time.Time }

type findingTrack struct {
	id          string
	start       time.Time
	raisedAt    time.Time
	verifiedAt  time.Time
	verified    bool
	lastMR      string
	deployAt    time.Time
	rerunAt     time.Time // first rerun on evidence newer than the deploy
	rerunClosed bool
	waits       []interval
}

// openWait is a refused merge that no later report has closed.
type openWait struct {
	finding string
	from    time.Time
}

// ExposureWindows folds the events into one window for each Finding. now ends
// the window of a Finding that is not verified. The result is sorted by ID.
func ExposureWindows(events []Event, now time.Time) []ExposureWindow {
	tracks := map[string]*findingTrack{}
	mrFindings := map[string][]string{}
	refused := map[string][]openWait{}
	// reverting holds the revert requests that no FixReverted has closed.
	reverting := map[string][]openWait{}
	track := func(id string) *findingTrack {
		t := tracks[id]
		if t == nil {
			t = &findingTrack{id: id}
			tracks[id] = t
		}
		return t
	}

	for _, raw := range events {
		switch e := deref(raw).(type) {
		case FindingRaised:
			t := track(e.ID)
			first := firstSeen(e)
			if t.start.IsZero() || (!first.IsZero() && first.Before(t.start)) {
				t.start = first
			}
			if t.raisedAt.IsZero() {
				t.raisedAt = e.At
				if !e.FirstSeenAt.IsZero() && e.FirstSeenAt.Before(e.At) {
					t.waits = append(t.waits, interval{e.FirstSeenAt, e.At})
				}
			}
		case FindingStatusChanged:
			t := track(e.ID)
			if e.MergeRequest != "" {
				t.lastMR = e.MergeRequest
				mrFindings[e.MergeRequest] = appendOnce(mrFindings[e.MergeRequest], e.ID)
			}
			switch e.Status {
			case FindingStatusVerified:
				if !t.verified {
					t.verified, t.verifiedAt = true, e.At
				}
			case FindingStatusOpen:
				t.verified, t.verifiedAt = false, time.Time{}
				t.deployAt, t.rerunAt, t.rerunClosed = time.Time{}, time.Time{}, false
			}
		case MergeRequestObserved:
			// Any report closes the open refusals of the merge request.
			for _, w := range refused[e.Key] {
				track(w.finding).waits = append(track(w.finding).waits, interval{w.from, e.At})
			}
			refused[e.Key] = nil
			if e.State == MergeRequestRefused {
				for _, id := range mrFindings[e.Key] {
					refused[e.Key] = append(refused[e.Key], openWait{finding: id, from: e.At})
				}
			}
		case DeployObserved:
			for _, id := range mrFindings[e.MergeRequest] {
				t := track(id)
				t.deployAt, t.rerunAt, t.rerunClosed = e.At, time.Time{}, false
			}
		case RevertRequested:
			if len(reverting[e.MergeRequest]) == 0 {
				for _, id := range mrFindings[e.MergeRequest] {
					reverting[e.MergeRequest] = append(reverting[e.MergeRequest], openWait{finding: id, from: e.At})
				}
			}
		case FixReverted:
			for _, w := range reverting[e.MergeRequest] {
				track(w.finding).waits = append(track(w.finding).waits, interval{w.from, e.At})
			}
			reverting[e.MergeRequest] = nil
		case CheckRerun:
			t := track(e.ID)
			if !t.deployAt.IsZero() && !t.rerunClosed && e.EvidenceAt.After(t.deployAt) {
				t.rerunAt, t.rerunClosed = e.EvidenceAt, true
			}
		}
	}

	out := make([]ExposureWindow, 0, len(tracks))
	for _, t := range tracks {
		if t.start.IsZero() {
			continue // no first evidence has a time, so there is no window
		}
		end := now
		if t.verified {
			end = t.verifiedAt
		}
		waits := t.waits
		for _, w := range reverting { // a revert that is not merged runs to the end
			for _, o := range w {
				if o.finding == t.id {
					waits = append(waits, interval{o.from, end})
				}
			}
		}
		for _, w := range refused { // a refusal that is still open runs to the end
			for _, o := range w {
				if o.finding == t.id {
					waits = append(waits, interval{o.from, end})
				}
			}
		}
		if !t.deployAt.IsZero() {
			to := end
			if t.rerunClosed {
				to = t.rerunAt
			}
			waits = append(waits, interval{t.deployAt, to})
		}
		win := ExposureWindow{FindingID: t.id, Start: t.start, End: end, Verified: t.verified}
		if end.After(t.start) {
			win.Total = end.Sub(t.start)
		}
		win.Wait = unionLength(waits, t.start, end)
		win.Agent = win.Total - win.Wait
		out = append(out, win)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out
}

// unionLength is the length of the union of the intervals, clipped to
// [from, to]. Two waits that overlap count once.
func unionLength(in []interval, from, to time.Time) time.Duration {
	clipped := make([]interval, 0, len(in))
	for _, iv := range in {
		if iv.from.Before(from) {
			iv.from = from
		}
		if iv.to.After(to) {
			iv.to = to
		}
		if iv.to.After(iv.from) {
			clipped = append(clipped, iv)
		}
	}
	sort.Slice(clipped, func(i, j int) bool { return clipped[i].from.Before(clipped[j].from) })
	var total time.Duration
	var cur *interval
	for i := range clipped {
		iv := clipped[i]
		if cur == nil || iv.from.After(cur.to) {
			if cur != nil {
				total += cur.to.Sub(cur.from)
			}
			c := iv
			cur = &c
			continue
		}
		if iv.to.After(cur.to) {
			cur.to = iv.to
		}
	}
	if cur != nil {
		total += cur.to.Sub(cur.from)
	}
	return total
}

func appendOnce(list []string, v string) []string {
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

// ExposureTrend is the median window of the verified Findings of a period, next
// to the median of the period before.
type ExposureTrend struct {
	// Count is the number of Findings verified in the period.
	Count  int
	Median time.Duration
	// MedianAgent and MedianWait are the medians of the two parts.
	MedianAgent time.Duration
	MedianWait  time.Duration
	// PreviousCount and PreviousMedian are the same for the period before.
	PreviousCount  int
	PreviousMedian time.Duration
}

// MedianExposure returns the median window of the Findings that were verified in
// (now-period, now], and the median of those verified in (now-2*period,
// now-period]. An open Finding is not in a median. It has no end yet.
func MedianExposure(windows []ExposureWindow, now time.Time, period time.Duration) ExposureTrend {
	var cur, prev []ExposureWindow
	for _, w := range windows {
		if !w.Verified {
			continue
		}
		switch {
		case w.End.After(now.Add(-period)) && !w.End.After(now):
			cur = append(cur, w)
		case w.End.After(now.Add(-2*period)) && !w.End.After(now.Add(-period)):
			prev = append(prev, w)
		}
	}
	return ExposureTrend{
		Count:          len(cur),
		Median:         medianOf(cur, func(w ExposureWindow) time.Duration { return w.Total }),
		MedianAgent:    medianOf(cur, func(w ExposureWindow) time.Duration { return w.Agent }),
		MedianWait:     medianOf(cur, func(w ExposureWindow) time.Duration { return w.Wait }),
		PreviousCount:  len(prev),
		PreviousMedian: medianOf(prev, func(w ExposureWindow) time.Duration { return w.Total }),
	}
}

func medianOf(ws []ExposureWindow, pick func(ExposureWindow) time.Duration) time.Duration {
	if len(ws) == 0 {
		return 0
	}
	vals := make([]time.Duration, len(ws))
	for i, w := range ws {
		vals[i] = pick(w)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	mid := len(vals) / 2
	if len(vals)%2 == 1 {
		return vals[mid]
	}
	return (vals[mid-1] + vals[mid]) / 2
}

// RevertStats counts the merged fixes of a period and the reverts among them.
type RevertStats struct {
	Merged   int
	Reverted int
	// Rate is Reverted divided by Merged. It is 0 when nothing merged.
	Rate float64
}

// RevertRate counts the merge requests that merged in [from, to) and, among
// them, the merge requests that an agent reverted. A merge request counts once.
func RevertRate(events []Event, from, to time.Time) RevertStats {
	merged := map[string]bool{}
	reverted := map[string]bool{}
	in := func(t time.Time) bool { return !t.Before(from) && t.Before(to) }
	for _, raw := range events {
		switch e := deref(raw).(type) {
		case MergeRequestObserved:
			if e.State == MergeRequestMerged && in(e.At) {
				merged[e.Key] = true
			}
		case FixReverted:
			if in(e.At) {
				reverted[e.MergeRequest] = true
			}
		}
	}
	stats := RevertStats{Merged: len(merged)}
	for mr := range reverted {
		if merged[mr] {
			stats.Reverted++
		}
	}
	if stats.Merged > 0 {
		stats.Rate = float64(stats.Reverted) / float64(stats.Merged)
	}
	return stats
}

// RevertTrend is the revert rate of the period that ends at now, next to the
// rate of the period before.
type RevertTrend struct {
	Current  RevertStats
	Previous RevertStats
}

// RevertRateTrend computes the revert rate of (now-period, now] and of the
// period before it.
func RevertRateTrend(events []Event, now time.Time, period time.Duration) RevertTrend {
	return RevertTrend{
		Current:  RevertRate(events, now.Add(-period), now.Add(time.Nanosecond)),
		Previous: RevertRate(events, now.Add(-2*period), now.Add(-period)),
	}
}

// deref turns a pointer event, as the codec decodes it, into the value event
// that a live Submit carries. Any other event passes through.
func deref(ev Event) Event {
	switch e := ev.(type) {
	case *FindingRaised:
		return *e
	case *FindingStatusChanged:
		return *e
	case *MergeRequestObserved:
		return *e
	case *DeployObserved:
		return *e
	case *CheckRerun:
		return *e
	case *FixReverted:
		return *e
	case *RevertRequested:
		return *e
	default:
		return ev
	}
}
