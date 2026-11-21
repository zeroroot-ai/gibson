// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"strconv"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// predicate_rerun.go is the producer of the CheckRerun of an attack predicate
// (review M11, ADR-0178). A finding that an attack predicate raised is fixed
// when the same predicate, on the same target, no longer holds on evidence
// newer than the deploy. The daemon evaluates the predicate itself on its own
// record of the tool calls (SettleBetTrue), so the rerun is the result of the
// daemon, never the word of an agent.

// recordedAtKey is the metadata key of the time of a recorded tool call
// (RecordedEvidence).
const recordedAtKey = "recorded_at_unix_nano"

// recordedEvidenceTime returns the time of the oldest item of the evidence. It
// returns false when an item is not the daemon record of a tool call, or has
// no time: text that an agent typed is no evidence of absence.
func recordedEvidenceTime(evidence []*typespb.Evidence) (time.Time, bool) {
	var oldest time.Time
	for _, ev := range evidence {
		if ev.GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_RECORDED {
			return time.Time{}, false
		}
		n, err := strconv.ParseInt(ev.GetMetadata()[recordedAtKey], 10, 64)
		if err != nil || n <= 0 {
			return time.Time{}, false
		}
		if t := time.Unix(0, n).UTC(); oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	return oldest, !oldest.IsZero()
}

// predicateReruns returns one CheckRerun for each `fixed` Finding that the
// predicate raised on the target. found is the result of the predicate on the
// evidence. The time of the evidence is the oldest recorded tool call, so a
// rerun reads as newer than the deploy only when each call is.
func predicateReruns(findings []FindingSnapshot, predicate, scopeID, missionID string, found bool, evidence []*typespb.Evidence) []Event {
	at, ok := recordedEvidenceTime(evidence)
	if !ok || predicate == "" || scopeID == "" {
		return nil
	}
	var out []Event
	for _, f := range findings {
		if f.Status != FindingStatusFixed || f.ScopeID != scopeID ||
			f.CheckKind != string(finding.CheckPredicate) || f.CheckRef != predicate {
			continue
		}
		out = append(out, CheckRerun{
			ID: f.ID, CheckKind: string(finding.CheckPredicate), Found: found, EvidenceAt: at, MissionID: missionID,
		})
	}
	return out
}
