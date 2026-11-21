// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// finding_place.go answers one question: which Application or Host does a
// finding touch (gibson#1519).
//
// A finding names its place in four ways. agent.Finding has a TargetID. The
// World Finding has a ScopeID and an Address. The graph has an AFFECTS edge to
// a Host or to a Package, and a FOUND_ON edge to a Target. ApplicationFinding
// has a place label and a place key. All four end in the same graph fact: the
// AFFECTS edge of the finding. This read starts from that edge and walks to the
// Application that reaches the place. It is the one function that the health
// signal, the one-at-a-time rule and the exposure window call.

// Labels of the two places that a fix can touch.
const (
	PlaceApplication = "Application"
	PlaceHost        = "Host"
)

// Place is the Application or the Host that a finding touches.
type Place struct {
	Label string `json:"label"`
	Key   string `json:"key"`
}

// ErrFindingNotFound means that the tenant graph holds no finding with the ID.
var ErrFindingNotFound = errors.New("graphrag: finding not found")

// applicationReachesPlace is true when the Application app reaches the node
// place by one of the four routes of the Taxonomy. applicationFindingsCypher
// and findingPlacesCypher both use it, so the two reads cannot disagree about
// which Application a finding belongs to.
const applicationReachesPlace = `
    EXISTS { (app)-[:HAS_DEPLOYMENT]->(:Deployment)-[:RUNS]->(:Image)-[:CONTAINS]->(place) }
    OR EXISTS { (app)-[:HAS_REPOSITORY]->(:Repository)<-[:BUILT_FROM]-(:Image)-[:CONTAINS]->(place) }
    OR EXISTS { (app)-[:HAS_REPOSITORY]->(place) }
    OR EXISTS { (app)-[:HAS_DEPLOYMENT]->(:Deployment)-[:EXPOSES]->(:Host)-[:RUNS_SERVICE]->(place) }
  `

// findingPlacesCypher returns one row for each place that the finding affects
// and each Application that reaches it. A finding that exists and affects
// nothing returns one row of nulls, so the caller can tell it from no finding.
const findingPlacesCypher = `
MATCH (f:Finding {brain_id: $finding})
OPTIONAL MATCH (f)-[:AFFECTS]->(place)
OPTIONAL MATCH (app:Application)
  WHERE place IS NOT NULL AND (` + applicationReachesPlace + `)
RETURN
  coalesce(head(labels(place)), '')       AS place_label,
  coalesce(place.key, place.brain_id, '') AS place_key,
  coalesce(app.key, '')                   AS application`

// findingPlacesManyCypher is findingPlacesCypher for a list of findings, in one
// read (review m9). Each row names its finding.
const findingPlacesManyCypher = `
UNWIND $findings AS fid
MATCH (f:Finding {brain_id: fid})
OPTIONAL MATCH (f)-[:AFFECTS]->(place)
OPTIONAL MATCH (app:Application)
  WHERE place IS NOT NULL AND (` + applicationReachesPlace + `)
RETURN
  fid                                     AS finding,
  coalesce(head(labels(place)), '')       AS place_label,
  coalesce(place.key, place.brain_id, '') AS place_key,
  coalesce(app.key, '')                   AS application`

// FindingPlacesMany returns the places of each finding of the list, in one
// read of the graph. A finding that the graph does not hold has no key in the
// map. A finding that affects nothing has an empty list.
func (q *PoolGraphRAGQuerier) FindingPlacesMany(ctx context.Context, tenant string, findingIDs []string) (map[string][]Place, error) {
	out := map[string][]Place{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	rows, err := q.readGraph(ctx, tenant, findingPlacesManyCypher, map[string]any{"findings": findingIDs})
	if err != nil {
		return nil, fmt.Errorf("finding places: %w", err)
	}
	byFinding := map[string][]map[string]any{}
	for _, r := range rows {
		id := stringField(r, "finding")
		byFinding[id] = append(byFinding[id], r)
	}
	for id, rs := range byFinding {
		out[id] = placesFromRows(rs)
	}
	return out, nil
}

// FindingPlaces returns the places that one finding touches. A place is an
// Application when one reaches the thing that the finding affects. It is the
// Host itself when the finding affects a Host and no Application reaches it. A
// finding that affects a Package that no Application reaches has no place, and
// the result is empty. It returns ErrFindingNotFound for an unknown finding.
func (q *PoolGraphRAGQuerier) FindingPlaces(ctx context.Context, tenant, findingID string) ([]Place, error) {
	if findingID == "" {
		return nil, errors.New("graphrag: finding places: finding id is required")
	}
	rows, err := q.readGraph(ctx, tenant, findingPlacesCypher, map[string]any{"finding": findingID})
	if err != nil {
		return nil, fmt.Errorf("finding places: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrFindingNotFound, findingID)
	}
	return placesFromRows(rows), nil
}

// placesFromRows maps the rows of findingPlacesCypher to places. It keeps an
// Application first, and a Host only when no Application reaches the same
// affected node. It returns the places in a stable order with no duplicate.
func placesFromRows(rows []map[string]any) []Place {
	seen := map[Place]bool{}
	var places []Place
	add := func(p Place) {
		if p.Key != "" && !seen[p] {
			seen[p] = true
			places = append(places, p)
		}
	}
	// A Host that an Application reaches is answered by the Application.
	reached := map[string]bool{}
	for _, r := range rows {
		if app := stringField(r, "application"); app != "" {
			reached[stringField(r, "place_key")] = true
			add(Place{Label: PlaceApplication, Key: app})
		}
	}
	for _, r := range rows {
		if stringField(r, "place_label") == PlaceHost && !reached[stringField(r, "place_key")] {
			add(Place{Label: PlaceHost, Key: stringField(r, "place_key")})
		}
	}
	sort.Slice(places, func(i, j int) bool {
		if places[i].Label != places[j].Label {
			return places[i].Label < places[j].Label
		}
		return places[i].Key < places[j].Key
	})
	return places
}
