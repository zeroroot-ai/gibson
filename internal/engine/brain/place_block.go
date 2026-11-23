package brain

import "time"

// FindingPlaceBlocked records the wait on a person that a finding shows because it
// has no single Application, or ends that wait when Reason is empty. The state is
// in the World, so a restart neither repeats the wait nor loses it (gibson#1469).
type FindingPlaceBlocked struct {
	ID        string
	Reason    string
	MissionID string
	At        time.Time
}

// Kind identifies the finding.place_blocked brain event.
func (FindingPlaceBlocked) Kind() string { return "finding.place_blocked" }

func applyFindingPlaceBlocked(w *World, e FindingPlaceBlocked) {
	forFinding(w, e.ID, func(f *Finding) { f.PlaceBlock = e.Reason })
}
