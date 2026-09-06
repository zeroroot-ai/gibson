// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

// ErrMissionInputAmbiguous is returned when a caller names both a checked-in
// mission and supplies its own graph, or neither. One RPC carries two ways of
// saying what to run, and exactly one of them must be used (ADR-0018).
var ErrMissionInputAmbiguous = errors.New("mission origination needs exactly one of mission_definition_json or catalog_mission")

// nullJSONBody is what a naive client sends when it marshals a nil mission
// definition: four bytes, not zero. Treating a non-empty body as "the caller
// supplied a graph" would then refuse every catalog origination from such a
// client for sending both, and the error would read as "the catalog path does
// not work" rather than "your client sent a literal null".
const nullJSONBody = "null"

// suppliedGraph reports whether the caller actually sent a mission graph.
//
// It is deliberately not a nil check: `json.Marshal(nil)` yields `null`, so
// absence arrives on the wire in two shapes and only one of them is empty.
func suppliedGraph(body string) bool {
	trimmed := strings.TrimSpace(body)
	return trimmed != "" && trimmed != nullJSONBody
}

// resolveMissionDefinitionJSON decides which graph a CreateMission call runs:
// the caller's own, or the checked-in catalog mission it named.
//
// It is a pure function of the request so the rules below are testable without
// a harness, a parent mission, or a daemon.
//
// The catalog path is what makes ADR-0018 true. Before it, the checked-in
// definition was authoritative in prose only — nothing could reference it, so
// the always-on agent kept a second copy of the graph, which is the duplicate
// ADR-0027 forbids.
func resolveMissionDefinitionJSON(ctx context.Context, req *harnesspb.CreateMissionRequest) (string, error) {
	graph := string(req.GetMissionDefinitionJson())
	name := strings.TrimSpace(req.GetCatalogMission())

	hasGraph := suppliedGraph(graph)
	hasCatalog := name != ""

	switch {
	case hasGraph && hasCatalog:
		return "", fmt.Errorf("%w: both were given, so it is unclear which to run", ErrMissionInputAmbiguous)
	case !hasGraph && !hasCatalog:
		return "", fmt.Errorf("%w: neither was given (checked-in missions: %s)",
			ErrMissionInputAmbiguous, strings.Join(missioncatalog.Names(), ", "))
	case hasGraph:
		// Parameters without a mission to apply them to are a caller error, not
		// something to drop: silently ignoring them would run the caller's graph
		// while they believed their parameters had bound.
		if len(req.GetCatalogParams()) > 0 {
			return "", fmt.Errorf("%w: catalog_params was given with a caller-supplied graph, which has no parameters to bind",
				ErrMissionInputAmbiguous)
		}
		return graph, nil
	}

	// Unknown keys are refused here, inside ParamsFromMap. That refusal is the
	// smuggling defence: Params carries no target or host, so a dropped
	// `host:` key would leave a caller believing it had redirected the scan.
	params, err := missioncatalog.ParamsFromMap(req.GetCatalogParams())
	if err != nil {
		return "", fmt.Errorf("originate %q: %w", name, err)
	}
	// Render reports every missing parameter at once, in declaration order, so
	// a caller wiring this up sees all of them rather than one per attempt.
	def, err := missioncatalog.Render(ctx, name, params)
	if err != nil {
		return "", fmt.Errorf("originate %q: %w", name, err)
	}
	body, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		return "", fmt.Errorf("marshal the rendered mission %q: %w", name, err)
	}
	return string(body), nil
}
