// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package harness

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

// catalogParams is a complete parameter set for one checked-in mission, built
// from THAT mission's own declaration. A parameter added to a mission shows up
// here as a render failure rather than as a test that quietly stops covering it.
//
// Per mission, not one set reused for all of them. These tests used to take
// missioncatalog.Names()[0] and feed it the scan mission's seven parameters;
// Names() is sorted, so adding cluster-assessment moved position 0 and three
// tests failed on parameters the mission does not take. A set that happened to
// fit whichever mission sorts first is a test that measures the sort order.
func catalogParams(t *testing.T, mission string) map[string]string {
	t.Helper()
	src, err := missioncatalog.Source(mission)
	if err != nil {
		t.Fatalf("Source(%s): %v", mission, err)
	}
	names, err := cueruntime.DeclaredParams(src)
	if err != nil {
		t.Fatalf("DeclaredParams(%s): %v", mission, err)
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		out[name] = "v-" + name
	}
	return out
}

func catalogReq(name string, params map[string]string) *harnesspb.CreateMissionRequest {
	return &harnesspb.CreateMissionRequest{CatalogMission: name, CatalogParams: params}
}

// A caller naming a checked-in mission gets the checked-in graph. This is the
// whole point of ADR-0118: before it, nothing could reference the definition,
// so the agent kept a second copy.
func TestResolveMissionDefinitionJSON_CatalogMissionRendersTheCheckedInGraph(t *testing.T) {
	t.Parallel()

	names := missioncatalog.Names()
	if len(names) == 0 {
		t.Skip("no checked-in missions to render")
	}
	for _, mission := range names {
		params := catalogParams(t, mission)
		body, err := resolveMissionDefinitionJSON(context.Background(), catalogReq(mission, params))
		if err != nil {
			t.Fatalf("resolveMissionDefinitionJSON(%s): %v", mission, err)
		}
		if !suppliedGraph(body) {
			t.Fatalf("%s: rendered body is empty or null: %q", mission, body)
		}
		// The rendered graph must carry EVERY parameter's value, not
		// placeholders. A declared parameter whose value does not appear is
		// either a substitution that did not happen or a parameter the mission
		// declares and never uses; both are worth a failure.
		for name, value := range params {
			if !strings.Contains(body, value) {
				t.Errorf("%s: the rendered graph does not carry the %q parameter: %s",
					mission, name, truncate(body))
			}
		}
	}
}

// The smuggling defence. Params has no target or host field, so a map that
// dropped unrecognised keys would let a caller send host: and believe it bound.
func TestResolveMissionDefinitionJSON_UnknownParameterIsRefusedNotDropped(t *testing.T) {
	t.Parallel()

	names := missioncatalog.Names()
	if len(names) == 0 {
		t.Skip("no checked-in missions")
	}
	params := catalogParams(t, names[0])
	params["host"] = "evil.example.com"

	_, err := resolveMissionDefinitionJSON(context.Background(), catalogReq(names[0], params))
	if err == nil {
		t.Fatal("an unknown parameter must be refused; dropping it would let a caller believe host: bound")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error %q does not name the unknown key", err.Error())
	}
}

// Every missing parameter at once: a caller wiring this up should not discover
// them one render at a time.
func TestResolveMissionDefinitionJSON_AllMissingParametersReportedTogether(t *testing.T) {
	t.Parallel()

	names := missioncatalog.Names()
	if len(names) == 0 {
		t.Skip("no checked-in missions")
	}
	params := catalogParams(t, names[0])
	if len(params) < 2 {
		t.Skipf("%s declares %d parameters; this asserts two missing at once", names[0], len(params))
	}
	// Two of the mission's OWN names, sorted so the choice does not depend on
	// map iteration order.
	declared := make([]string, 0, len(params))
	for name := range params {
		declared = append(declared, name)
	}
	sort.Strings(declared)
	missing := declared[:2]
	for _, name := range missing {
		delete(params, name)
	}

	_, err := resolveMissionDefinitionJSON(context.Background(), catalogReq(names[0], params))
	if err == nil {
		t.Fatal("a missing parameter must fail the render")
	}
	for _, want := range missing {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name the missing parameter %q", err.Error(), want)
		}
	}
}

// One RPC, two ways of saying what to run, exactly one of them used.
func TestResolveMissionDefinitionJSON_BothOrNeitherIsRefused(t *testing.T) {
	t.Parallel()

	both := &harnesspb.CreateMissionRequest{
		MissionDefinitionJson: []byte(`{"name":"hand-written"}`),
		CatalogMission:        "scan",
	}
	if _, err := resolveMissionDefinitionJSON(context.Background(), both); !errors.Is(err, ErrMissionInputAmbiguous) {
		t.Fatalf("both inputs: error = %v; want ErrMissionInputAmbiguous", err)
	}

	neither := &harnesspb.CreateMissionRequest{}
	err := resolveMissionDefinitionJSON2(t, neither)
	if !errors.Is(err, ErrMissionInputAmbiguous) {
		t.Fatalf("neither input: error = %v; want ErrMissionInputAmbiguous", err)
	}
	// The refusal names what is available, because "neither was given" without
	// the list sends the reader to the source to find out what to name.
	if names := missioncatalog.Names(); len(names) > 0 && !strings.Contains(err.Error(), names[0]) {
		t.Errorf("error %q does not list the checked-in missions", err.Error())
	}
}

func resolveMissionDefinitionJSON2(t *testing.T, req *harnesspb.CreateMissionRequest) error {
	t.Helper()
	_, err := resolveMissionDefinitionJSON(context.Background(), req)
	return err
}

// A literal `null` body is how a naive client says "no graph". Reading it as a
// supplied graph would refuse every catalog origination from such a client for
// sending both — and the error would read as "the catalog path is broken".
func TestResolveMissionDefinitionJSON_NullBodyIsAbsenceNotAGraph(t *testing.T) {
	t.Parallel()

	names := missioncatalog.Names()
	if len(names) == 0 {
		t.Skip("no checked-in missions")
	}
	req := catalogReq(names[0], catalogParams(t, names[0]))
	req.MissionDefinitionJson = []byte("null")

	if _, err := resolveMissionDefinitionJSON(context.Background(), req); err != nil {
		t.Fatalf("a null body alongside a catalog mission must be treated as absence, got %v", err)
	}

	// But `null` with nothing else named is still "neither", not a runnable graph.
	only := &harnesspb.CreateMissionRequest{MissionDefinitionJson: []byte("null")}
	if _, err := resolveMissionDefinitionJSON(context.Background(), only); !errors.Is(err, ErrMissionInputAmbiguous) {
		t.Fatalf("a null body alone: error = %v; want ErrMissionInputAmbiguous", err)
	}
}

// Parameters with no catalog mission are a caller error. Dropping them would
// run the caller's own graph while they believed their parameters had bound.
func TestResolveMissionDefinitionJSON_ParamsWithAGraphIsRefused(t *testing.T) {
	t.Parallel()

	req := &harnesspb.CreateMissionRequest{
		MissionDefinitionJson: []byte(`{"name":"hand-written"}`),
		CatalogParams:         map[string]string{"application": "app"},
	}
	if _, err := resolveMissionDefinitionJSON(context.Background(), req); !errors.Is(err, ErrMissionInputAmbiguous) {
		t.Fatalf("error = %v; want ErrMissionInputAmbiguous", err)
	}
}

// The existing path is untouched: a caller-supplied graph passes through byte
// for byte, because every current caller uses it.
func TestResolveMissionDefinitionJSON_SuppliedGraphPassesThrough(t *testing.T) {
	t.Parallel()

	const graph = `{"name":"hand-written","nodes":{}}`
	body, err := resolveMissionDefinitionJSON(context.Background(),
		&harnesspb.CreateMissionRequest{MissionDefinitionJson: []byte(graph)})
	if err != nil {
		t.Fatalf("resolveMissionDefinitionJSON: %v", err)
	}
	if body != graph {
		t.Fatalf("body = %q; want the caller's graph unchanged", body)
	}
}

// An unknown mission name fails loudly and lists what exists, rather than
// rendering nothing and reporting a mission with no nodes.
func TestResolveMissionDefinitionJSON_UnknownMissionNameIsRefused(t *testing.T) {
	t.Parallel()

	_, err := resolveMissionDefinitionJSON(context.Background(), catalogReq("no-such-mission", catalogParams(t, missioncatalog.Names()[0])))
	if err == nil {
		t.Fatal("an unknown mission name must be refused")
	}
	if !strings.Contains(err.Error(), "no-such-mission") {
		t.Errorf("error %q does not name the mission that does not exist", err.Error())
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// TestCreateMission_NeitherInputIsInvalidArgument pins the rule at the handler,
// not just in the pure function: the refusal must reach the caller as
// INVALID_ARGUMENT in the response's error field, which is where an agent
// actually reads it.
//
// This is a deliberate behaviour change. Before gibson#1688 an origination with
// no definition was accepted and created a mission with no graph — a mission
// that runs nothing, reported as success.
func TestCreateMission_NeitherInputIsInvalidArgument(t *testing.T) {
	mgr := &recordingMissionOperator{}
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")

	req := originRequest()
	req.MissionDefinitionJson = nil

	resp, err := svc.CreateMission(originCtx(), req)
	if err != nil {
		t.Fatalf("CreateMission returned a transport error: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatal("origination with neither a graph nor a catalog mission must be refused")
	}
	if got := resp.GetError().GetCode(); got != commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Errorf("code = %v; want INVALID_ARGUMENT", got)
	}
	if mgr.got != nil {
		t.Error("the mission manager must not be called for a request that names no graph")
	}
}
