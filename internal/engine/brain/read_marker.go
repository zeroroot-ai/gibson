// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "sort"

// ReadMarker records how far one agent read the results of one Connector
// (gibson#1569). The key is the authenticated identity of the agent and the
// name of the Connector. The World of the tenant holds the marker, so the
// tenant is the third part of the key. The identity comes from the auth
// context of the call and never from a field that the caller sets.
type ReadMarker struct {
	// Subject is the authenticated identity of the component that wrote the
	// marker.
	Subject string `json:"subject"`
	// Connector is the name of the ConnectorInstance that the agent read.
	Connector string `json:"connector"`
	// Cursor is the position in the results of the Connector. The daemon does
	// not read it.
	Cursor string `json:"cursor,omitempty"`
	// ResultIDs names the results that the agent read at the cursor.
	ResultIDs []string `json:"result_ids,omitempty"`
	// RecordedAtUnixNano is set by the daemon and carried on the event, so a
	// replay gives the same World.
	RecordedAtUnixNano int64 `json:"recorded_at_unix_nano"`
}

// ReadMarkerWritten records one write of a read marker. The last write for a
// subject and a Connector is the marker.
type ReadMarkerWritten ReadMarker

// Kind identifies this event on the Timeline.
func (ReadMarkerWritten) Kind() string { return "read_marker.written" }

type readMarkerKey struct{ subject, connector string }

func applyReadMarkerWritten(w *World, e ReadMarkerWritten) {
	if e.Subject == "" || e.Connector == "" {
		return
	}
	if w.readMarkers == nil {
		w.readMarkers = map[readMarkerKey]ReadMarker{}
	}
	k := readMarkerKey{e.Subject, e.Connector}
	// A write that the Timeline replays out of order does not move the marker
	// back.
	if old, ok := w.readMarkers[k]; ok && old.RecordedAtUnixNano > e.RecordedAtUnixNano {
		return
	}
	m := ReadMarker(e)
	m.ResultIDs = append([]string(nil), e.ResultIDs...)
	w.readMarkers[k] = m
}

// LastReadMarker returns the last marker that the subject wrote for the
// Connector. The bool is false when the subject wrote none.
func (w *World) LastReadMarker(subject, connector string) (ReadMarker, bool) {
	m, ok := w.readMarkers[readMarkerKey{subject, connector}]
	if !ok {
		return ReadMarker{}, false
	}
	m.ResultIDs = append([]string(nil), m.ResultIDs...)
	return m, true
}

// ReadMarkerSnapshot returns the markers for a snapshot, in a fixed order.
func (w *World) ReadMarkerSnapshot() []ReadMarker {
	if len(w.readMarkers) == 0 {
		return nil
	}
	out := make([]ReadMarker, 0, len(w.readMarkers))
	for _, m := range w.readMarkers {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Connector < out[j].Connector
	})
	return out
}
