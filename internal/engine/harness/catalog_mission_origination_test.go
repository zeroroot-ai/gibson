// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

// scanParams is a complete parameter set for the checked-in scan mission,
// built from the catalog's own declaration so a parameter added there shows up
// here as a render failure rather than as a test that quietly stops covering it.
func scanParams() map[string]string {
	out := map[string]string{}
	for _, name := range missioncatalog.ParamNames() {
		out[name] = "v-" + name
	}
	return out
}

func catalogReq(name string, params map[string]string) *harnesspb.CreateMissionRequest {
	return &harnesspb.CreateMissionRequest{CatalogMission: name, CatalogParams: params}
}

// A caller naming a checked-in mission gets the checked-in graph. This is the
// whole point of ADR-0018: before it, nothing could reference the definition,
// so the agent kept a second copy.
func TestResolveMissionDefinitionJSON_CatalogMissionRendersTheCheckedInGraph(t *testing.T) {
	t.Parallel()

	names := missioncatalog.Names()
	if len(names) == 0 {
		t.Skip("no checked-in missions to render")
	}
	body, err := resolveMissionDefinitionJSON(context.Background(), catalogReq(names[0], scanParams()))
	if err != nil {
		t.Fatalf("resolveMissionDefinitionJSON: %v", err)
	}
	if !suppliedGraph(body) {
		t.Fatalf("rendered body is empty or null: %q", body)
	}
	// The rendered graph must carry the parameters, not placeholders.
	if !strings.Contains(body, "v-application") {
		t.Errorf("rendered graph does not carry the application parameter: %s", truncate(body))
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
	params := scanParams()
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
	params := scanParams()
	delete(params, "ref")
	delete(params, "commit")

	_, err := resolveMissionDefinitionJSON(context.Background(), catalogReq(names[0], params))
	if err == nil {
		t.Fatal("a missing parameter must fail the render")
	}
	for _, want := range []string{"ref", "commit"} {
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
	req := catalogReq(names[0], scanParams())
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

	_, err := resolveMissionDefinitionJSON(context.Background(), catalogReq("no-such-mission", scanParams()))
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
