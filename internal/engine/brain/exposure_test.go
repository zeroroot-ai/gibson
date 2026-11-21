// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"
)

func hours(n int) time.Duration { return time.Duration(n) * time.Hour }

func window(t *testing.T, events []Event, now time.Time) ExposureWindow {
	t.Helper()
	ws := ExposureWindows(events, now)
	if len(ws) != 1 {
		t.Fatalf("windows = %v, want 1", ws)
	}
	return ws[0]
}

// The window of a verified finding runs from its first event to the verified
// event.
func TestExposure_VerifiedWindow(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1", At: at(0)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified, At: at(6)},
	}
	w := window(t, events, at(100))
	if !w.Verified || w.Total != hours(6) || w.Wait != 0 || w.Agent != hours(6) {
		t.Fatalf("window = %+v, want 6h total, no wait", w)
	}
}

// The window of an open finding grows with the clock.
func TestExposure_OpenWindowGrowsWithTheClock(t *testing.T) {
	events := []Event{FindingRaised{ID: "f1", At: at(0)}}
	a, b := window(t, events, at(2)), window(t, events, at(5))
	if a.Verified || a.Total != hours(2) || b.Total != hours(5) {
		t.Fatalf("windows = %+v and %+v", a, b)
	}
}

// For a finding from a tool of the buyer the window starts when the tool first
// saw the flaw. The time before the read is wait time.
func TestExposure_ToolFirstSightStartsTheWindowAndIsWait(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1", At: at(5), FirstSeenAt: at(0)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified, At: at(8)},
	}
	w := window(t, events, at(100))
	if w.Total != hours(8) || w.Wait != hours(5) || w.Agent != hours(3) {
		t.Fatalf("window = %+v, want 8h total, 5h wait, 3h agent", w)
	}
}

// Wait time holds the time of a refused merge and the wait for the next scan.
func TestExposure_RefusedMergeAndNextScanAreWait(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1", At: at(0)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)},
		MergeRequestObserved{Key: "mr-1", State: MergeRequestRefused, At: at(2)}, // a person must approve
		MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged, At: at(5)},  // 3h of wait
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixed, At: at(5)},
		DeployObserved{MergeRequest: "mr-1", At: at(6)},
		CheckRerun{ID: "f1", CheckKind: "scan", EvidenceAt: at(10)}, // 4h until the next scan
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified, At: at(11)},
	}
	w := window(t, events, at(100))
	if w.Total != hours(11) || w.Wait != hours(7) || w.Agent != hours(4) {
		t.Fatalf("window = %+v, want 11h total, 7h wait, 4h agent", w)
	}
}

// The time that a merge request waits in the one-at-a-time queue is agent time.
func TestExposure_TimeInTheMergeQueueIsAgentTime(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1", At: at(0)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)},
		MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1)},
		MergeGranted{MergeRequest: "mr-1", Application: "shop", At: at(4)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified, At: at(6)},
	}
	if w := window(t, events, at(100)); w.Wait != 0 || w.Agent != hours(6) {
		t.Fatalf("window = %+v, want all agent time", w)
	}
}

// Two waits that overlap count once.
func TestExposure_OverlappingWaitsCountOnce(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1", At: at(4), FirstSeenAt: at(0)}, // wait 0 to 4
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)},
		MergeRequestObserved{Key: "mr-1", State: MergeRequestRefused, At: at(2)}, // wait 2 to 6
		MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged, At: at(6)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified, At: at(8)},
	}
	if w := window(t, events, at(100)); w.Wait != hours(6) {
		t.Fatalf("wait = %v, want 6h", w.Wait)
	}
}

// Replay of the Timeline gives the same numbers: the events decoded from the
// codec, as pointers, give the same windows as the live values.
func TestExposure_ReplayGivesTheSameNumbers(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1", At: at(0)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)},
		MergeRequestObserved{Key: "mr-1", State: MergeRequestRefused, At: at(2)},
		MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged, At: at(4)},
		DeployObserved{MergeRequest: "mr-1", At: at(5)},
		CheckRerun{ID: "f1", CheckKind: "scan", EvidenceAt: at(7)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified, At: at(8)},
	}
	decoded := make([]Event, 0, len(events))
	for _, ev := range events {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, got)
	}
	live, replayed := ExposureWindows(events, at(50)), ExposureWindows(decoded, at(50))
	if len(live) != 1 || len(replayed) != 1 {
		t.Fatalf("live = %+v, replayed = %+v", live, replayed)
	}
	a, b := live[0], replayed[0]
	if a.Total != b.Total || a.Wait != b.Wait || a.Agent != b.Agent || a.Verified != b.Verified || a.Total != hours(8) {
		t.Fatalf("live = %+v, replayed = %+v", a, b)
	}
}

func TestMedianExposure_UsesVerifiedWindowsOfThePeriod(t *testing.T) {
	now := at(100)
	ws := []ExposureWindow{
		{FindingID: "a", Verified: true, End: now.Add(-hours(1)), Total: hours(2), Wait: hours(1), Agent: hours(1)},
		{FindingID: "b", Verified: true, End: now.Add(-hours(2)), Total: hours(10), Wait: hours(4), Agent: hours(6)},
		{FindingID: "c", Verified: true, End: now.Add(-hours(3)), Total: hours(4), Wait: hours(2), Agent: hours(2)},
		{FindingID: "old", Verified: true, End: now.Add(-hours(30)), Total: hours(20)},
		{FindingID: "open", Verified: false, End: now, Total: hours(99)},
	}
	got := MedianExposure(ws, now, hours(24))
	if got.Count != 3 || got.Median != hours(4) || got.MedianWait != hours(2) || got.MedianAgent != hours(2) {
		t.Fatalf("trend = %+v", got)
	}
	if got.PreviousCount != 1 || got.PreviousMedian != hours(20) {
		t.Fatalf("previous = %+v", got)
	}
}

// A tenant with ten merged fixes and one revert has a revert rate of 10 percent.
func TestRevertRate_TenMergedOneReverted(t *testing.T) {
	events := make([]Event, 0, 12)
	for i := range 10 {
		events = append(events, MergeRequestObserved{Key: string(rune('a' + i)), State: MergeRequestMerged, At: at(i)})
	}
	events = append(events,
		FixReverted{MergeRequest: "c", At: at(12)},
		FixReverted{MergeRequest: "c", At: at(13)}, // one merge request counts once
	)
	got := RevertRate(events, at(0), at(24))
	if got.Merged != 10 || got.Reverted != 1 || got.Rate != 0.1 {
		t.Fatalf("stats = %+v, want 10 merged, 1 reverted, 0.1", got)
	}
}

func TestRevertRate_ReplayAndTrend(t *testing.T) {
	events := []Event{
		MergeRequestObserved{Key: "old-1", State: MergeRequestMerged, At: at(1)},
		MergeRequestObserved{Key: "old-2", State: MergeRequestMerged, At: at(2)},
		FixReverted{MergeRequest: "old-1", At: at(3)},
		MergeRequestObserved{Key: "new-1", State: MergeRequestMerged, At: at(30)},
		MergeRequestObserved{Key: "new-2", State: MergeRequestMerged, At: at(31)},
		MergeRequestObserved{Key: "new-3", State: MergeRequestMerged, At: at(32)},
		MergeRequestObserved{Key: "new-4", State: MergeRequestMerged, At: at(33)},
	}
	decoded := make([]Event, 0, len(events))
	for _, ev := range events {
		data, _ := EncodeEvent(ev)
		got, err := DecodeEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, got)
	}
	live, replayed := RevertRateTrend(events, at(40), hours(24)), RevertRateTrend(decoded, at(40), hours(24))
	if live != replayed {
		t.Fatalf("live = %+v, replayed = %+v", live, replayed)
	}
	if live.Current.Merged != 4 || live.Current.Rate != 0 || live.Previous.Merged != 2 || live.Previous.Reverted != 1 {
		t.Fatalf("trend = %+v", live)
	}
}

// A revert counts in the period of the revert, also when the merge was in the
// period before (review m5).
func TestRevertRate_ARevertCountsInThePeriodOfTheRevert(t *testing.T) {
	events := []Event{
		MergeRequestObserved{Key: "a", State: MergeRequestMerged, At: at(10)},
		FixReverted{MergeRequest: "a", At: at(26)},
		MergeRequestObserved{Key: "b", State: MergeRequestMerged, At: at(27)},
	}
	got := RevertRateTrend(events, at(40), hours(24))
	if got.Current.Merged != 1 || got.Current.Reverted != 1 || got.Previous.Merged != 1 || got.Previous.Reverted != 0 {
		t.Fatalf("trend = %+v, want the revert in the current period", got)
	}
}
