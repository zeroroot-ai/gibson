// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — catalog_missions_test.go unit tests for
// DaemonService.ListCatalogMissions and DaemonService.RenderCatalogMission.
//
// Spec: gibson#631 (a person cannot submit a catalog mission).
package api

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

func catalogServer() *DaemonServer {
	return &DaemonServer{logger: slog.New(slog.DiscardHandler)}
}

// The listing is the whole catalog, and it names what each mission needs. A
// listing that returned nothing would read as "the platform ships no missions".
func TestListCatalogMissions_ListsEveryCheckedInMissionWithItsParameters(t *testing.T) {
	t.Parallel()

	resp, err := catalogServer().ListCatalogMissions(context.Background(), &daemonpb.ListCatalogMissionsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogMissions: %v", err)
	}

	want := missioncatalog.Names()
	if len(want) == 0 {
		t.Fatal("the embedded catalog is empty; this test would pass on anything")
	}
	got := make([]string, 0, len(resp.GetMissions()))
	for _, m := range resp.GetMissions() {
		got = append(got, m.GetName())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("listed %v, want %v in that order", got, want)
	}

	for _, m := range resp.GetMissions() {
		// The description and version come from the rendered definition, not
		// from a second table that would drift from the mission it describes.
		if m.GetDescription() == "" {
			t.Errorf("%s: no description", m.GetName())
		}
		if m.GetVersion() == "" {
			t.Errorf("%s: no version", m.GetName())
		}
		// declared_params must BE the closed set, because a caller builds its
		// render request from it. A short list sends a render that fails on a
		// missing key; a long one fails on an unknown key.
		src, serr := missioncatalog.Source(m.GetName())
		if serr != nil {
			t.Fatalf("Source(%s): %v", m.GetName(), serr)
		}
		declared, derr := cueruntime.DeclaredParams(src)
		if derr != nil {
			t.Fatalf("DeclaredParams(%s): %v", m.GetName(), derr)
		}
		slices.Sort(declared)
		if !slices.Equal(m.GetDeclaredParams(), declared) {
			t.Errorf("%s: declared_params = %v, want %v", m.GetName(), m.GetDeclaredParams(), declared)
		}
	}
}

// The listing is assembled from missioncatalog.Entries and nothing else, so
// the two cannot answer the same question differently. It used to render each
// mission against PLACEHOLDER parameter values just to read its description,
// which was three failure modes and a set of fake values in exchange for three
// string literals.
func TestListCatalogMissions_IsExactlyWhatTheCatalogDescribes(t *testing.T) {
	t.Parallel()

	resp, err := catalogServer().ListCatalogMissions(context.Background(), &daemonpb.ListCatalogMissionsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogMissions: %v", err)
	}
	entries, err := missioncatalog.Entries()
	if err != nil {
		t.Fatalf("missioncatalog.Entries: %v", err)
	}
	if len(resp.GetMissions()) != len(entries) {
		t.Fatalf("the RPC listed %d missions, the catalog describes %d",
			len(resp.GetMissions()), len(entries))
	}
	for i, m := range resp.GetMissions() {
		e := entries[i]
		if m.GetName() != e.Name || m.GetDescription() != e.Description || m.GetVersion() != e.Version {
			t.Errorf("entry %d = %q/%q/%q, want %q/%q/%q", i,
				m.GetName(), m.GetDescription(), m.GetVersion(), e.Name, e.Description, e.Version)
		}
		if !slices.Equal(m.GetDeclaredParams(), e.DeclaredParams) {
			t.Errorf("%s: declared_params = %v, want %v", m.GetName(), m.GetDeclaredParams(), e.DeclaredParams)
		}
	}
}

// A caller that builds its request from the listing can render.
func TestRenderCatalogMission_RendersWhatTheListingDeclared(t *testing.T) {
	t.Parallel()

	srv := catalogServer()
	listed, err := srv.ListCatalogMissions(context.Background(), &daemonpb.ListCatalogMissionsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogMissions: %v", err)
	}

	for _, m := range listed.GetMissions() {
		params := make(map[string]string, len(m.GetDeclaredParams()))
		for _, name := range m.GetDeclaredParams() {
			params[name] = placeholderParam(name)
			if name == "forgeConnector" && m.GetName() == "scan" {
				params[name] = "github-fixloop" // an enum
			}
		}

		resp, rerr := srv.RenderCatalogMission(context.Background(),
			&daemonpb.RenderCatalogMissionRequest{Name: m.GetName(), Params: params})
		if rerr != nil {
			t.Fatalf("RenderCatalogMission(%s): %v", m.GetName(), rerr)
		}
		if resp.GetMission().GetName() != m.GetName() {
			t.Errorf("%s: rendered mission is named %q", m.GetName(), resp.GetMission().GetName())
		}
		if len(resp.GetMission().GetNodes()) == 0 {
			t.Errorf("%s: rendered definition has no nodes", m.GetName())
		}
		// The source is returned verbatim so a person reads what the daemon
		// will run rather than trusting a rendered summary.
		if !strings.Contains(resp.GetSource(), "mission:") {
			t.Errorf("%s: the returned source does not look like the mission's CUE", m.GetName())
		}
	}
}

// The smuggling defence, on this path too. No mission declares a target or a
// host, so a dropped key would leave a caller believing it had redirected the
// scan. Asserted here rather than inferred from the shared resolver.
func TestRenderCatalogMission_UnknownParameterIsRefusedNotDropped(t *testing.T) {
	t.Parallel()

	srv := catalogServer()
	name := missioncatalog.Names()[0]
	src, _ := missioncatalog.Source(name)
	declared, _ := cueruntime.DeclaredParams(src)

	params := map[string]string{"host": "evil.example.com"}
	for _, d := range declared {
		params[d] = placeholderParam(d)
	}

	_, err := srv.RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: name, Params: params})
	if err == nil {
		t.Fatal("an unknown parameter must be refused; dropping it would let a caller believe host: bound")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("the refusal does not name the unknown key: %v", err)
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// The property the closed set exists for, said as its own test: a parameter
// cannot supply the target.
//
// The runtime target binds from the mission's target at submit and from nowhere
// else, so a caller that could smuggle one through a parameter could point a
// run at a cluster the tenant never registered. No mission declares `target`,
// `host`, `url` or `targetRef`, and each is refused by name rather than
// dropped.
func TestRenderCatalogMission_AParameterCannotSupplyTheTarget(t *testing.T) {
	t.Parallel()

	srv := catalogServer()
	for _, mission := range missioncatalog.Names() {
		src, serr := missioncatalog.Source(mission)
		if serr != nil {
			t.Fatalf("Source(%s): %v", mission, serr)
		}
		declared, derr := cueruntime.DeclaredParams(src)
		if derr != nil {
			t.Fatalf("DeclaredParams(%s): %v", mission, derr)
		}

		for _, smuggled := range []string{"target", "targetRef", "host", "url"} {
			// A mission that DID declare one of these would make the check
			// vacuous, so say so rather than passing quietly.
			if slices.Contains(declared, smuggled) {
				t.Fatalf("mission %q declares a parameter named %q; the runtime target must not be caller-supplied",
					mission, smuggled)
			}

			params := map[string]string{smuggled: "evil.example.com"}
			for _, d := range declared {
				params[d] = placeholderParam(d)
			}
			_, err := srv.RenderCatalogMission(context.Background(),
				&daemonpb.RenderCatalogMissionRequest{Name: mission, Params: params})
			if err == nil {
				t.Errorf("mission %q accepted a %q parameter", mission, smuggled)
				continue
			}
			if !strings.Contains(err.Error(), smuggled) {
				t.Errorf("mission %q: the refusal does not name %q: %v", mission, smuggled, err)
			}
		}
	}
}

// Every missing parameter at once. A caller wiring this up should not discover
// them one render at a time.
func TestRenderCatalogMission_MissingParametersReportedTogether(t *testing.T) {
	t.Parallel()

	name := missioncatalog.Names()[0]
	src, _ := missioncatalog.Source(name)
	declared, _ := cueruntime.DeclaredParams(src)
	if len(declared) < 2 {
		t.Skipf("%s declares %d parameters; this asserts two missing at once", name, len(declared))
	}
	slices.Sort(declared)

	_, err := catalogServer().RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: name, Params: map[string]string{}})
	if err == nil {
		t.Fatal("a render with no parameters must fail for a mission that takes some")
	}
	for _, want := range declared[:2] {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the missing parameter %q: %v", want, err)
		}
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// An unknown name is the caller's mistake, and the error names what the catalog
// does ship — which is what a person needs after a typo.
func TestRenderCatalogMission_UnknownNameNamesWhatExists(t *testing.T) {
	t.Parallel()

	_, err := catalogServer().RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: "no-such-mission"})
	if err == nil {
		t.Fatal("an unknown mission name must be refused")
	}
	for _, want := range missioncatalog.Names() {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the checked-in mission %q: %v", want, err)
		}
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// A name is required, and the refusal lists the catalog rather than just
// saying "name is required".
func TestRenderCatalogMission_EmptyNameIsRefused(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "   "} {
		_, err := catalogServer().RenderCatalogMission(context.Background(),
			&daemonpb.RenderCatalogMissionRequest{Name: name})
		if err == nil {
			t.Fatalf("name %q was accepted", name)
		}
		assertGRPCStatusCode(t, err, "InvalidArgument")
	}
}

// A path instead of a name is refused, so a caller cannot read a file outside
// the embedded catalog.
func TestRenderCatalogMission_APathIsNotAName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"../scan", "missions/scan", "scan.cue"} {
		_, err := catalogServer().RenderCatalogMission(context.Background(),
			&daemonpb.RenderCatalogMissionRequest{Name: name})
		if err == nil {
			t.Errorf("name %q was accepted as a mission name", name)
		}
	}
}

// The person path and the agent path must render the SAME definition for the
// same inputs. Two resolutions of one catalog is the duplicate ADR-0027
// forbids, and this is what keeps them one.
func TestRenderCatalogMission_AgreesWithTheAgentPath(t *testing.T) {
	t.Parallel()

	name := missioncatalog.Names()[0]
	src, _ := missioncatalog.Source(name)
	declared, _ := cueruntime.DeclaredParams(src)
	params := make(map[string]string, len(declared))
	for _, d := range declared {
		params[d] = placeholderParam(d)
	}

	resp, err := catalogServer().RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: name, Params: params})
	if err != nil {
		t.Fatalf("RenderCatalogMission: %v", err)
	}

	// missioncatalog.Render is what the harness callback calls. Same function,
	// so this asserts this handler adds no second rendering step of its own.
	want, err := missioncatalog.Render(context.Background(), name, params)
	if err != nil {
		t.Fatalf("missioncatalog.Render: %v", err)
	}
	if got, exp := len(resp.GetMission().GetNodes()), len(want.GetNodes()); got != exp {
		t.Errorf("the person path rendered %d nodes, the agent path %d", got, exp)
	}
	if resp.GetMission().GetName() != want.GetName() {
		t.Errorf("names differ: %q vs %q", resp.GetMission().GetName(), want.GetName())
	}
}

// A person runs a catalog mission by name. The handler refuses what the render
// refuses, before any mission exists, and it passes the name, the params and the
// target to the daemon.
func TestRunCatalogMission_RendersThenStartsTheMission(t *testing.T) {
	t.Parallel()

	var got RunCatalogMissionData
	called := 0
	daemon := &mockDaemon{runCatalogMissionFn: func(_ context.Context, req RunCatalogMissionData) (string, error) {
		called++
		got = req
		return "mission-7", nil
	}}
	srv := NewDaemonServer(daemon, nil, nil)
	params := map[string]string{"repositoryUrl": "https://github.com/acme/shop", "application": "acme/shop", "forgeConnector": "github-fixloop"}

	resp, err := srv.RunCatalogMission(callerCtx(), &daemonpb.RunCatalogMissionRequest{
		Name: "scan", Params: params, TargetId: "target-1",
	})
	if err != nil {
		t.Fatalf("RunCatalogMission: %v", err)
	}
	if resp.GetMissionId() != "mission-7" || called != 1 {
		t.Errorf("mission id = %q, calls = %d", resp.GetMissionId(), called)
	}
	if got.Name != "scan" || got.TargetID != "target-1" || got.Params["application"] != "acme/shop" {
		t.Errorf("the daemon got %+v", got)
	}

	for name, req := range map[string]*daemonpb.RunCatalogMissionRequest{
		"no name":         {Params: params, TargetId: "target-1"},
		"unknown mission": {Name: "nothing", Params: params, TargetId: "target-1"},
		"no target":       {Name: "scan", Params: params},
		"unknown param":   {Name: "scan", Params: map[string]string{"host": "evil.example.com", "forgeConnector": "github-fixloop"}, TargetId: "target-1"},
		"no branch":       {Name: "scan", Params: map[string]string{"application": "acme/shop"}, TargetId: "target-1"},
	} {
		before := called
		if _, rerr := srv.RunCatalogMission(callerCtx(), req); status_grpc.Code(rerr) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, rerr)
		}
		if called != before {
			t.Errorf("%s: the daemon was called for a refused request", name)
		}
	}
}

// An error of the daemon reaches the caller, and no mission id comes with it.
func TestRunCatalogMission_ADaemonErrorIsReturned(t *testing.T) {
	t.Parallel()
	daemon := &mockDaemon{runCatalogMissionFn: func(context.Context, RunCatalogMissionData) (string, error) {
		return "", status_grpc.Error(codes.NotFound, "target not found")
	}}
	srv := NewDaemonServer(daemon, nil, nil)
	resp, err := srv.RunCatalogMission(callerCtx(), &daemonpb.RunCatalogMissionRequest{
		Name: "scan", TargetId: "t", Params: map[string]string{"imageRef": "r/i@sha256:abc"},
	})
	if status_grpc.Code(err) != codes.NotFound || resp != nil {
		t.Errorf("resp = %v, err = %v, want NotFound", resp, err)
	}
}

// callerCtx is the context of a verified caller.
func callerCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "user:alice"})
}

// A mission that a person creates by hand may not take the name of a checked-in
// mission, and a marker in the metadata that a caller sends is removed
// (gibson#1469).
func TestCreateMission_ACatalogNameIsReservedAndTheMarkerIsRemoved(t *testing.T) {
	t.Parallel()
	var got CreateMissionData
	daemon := &mockDaemon{createMissionFn: func(_ context.Context, req CreateMissionData) (CreateMissionResultData, error) {
		got = req
		return CreateMissionResultData{MissionID: "m1", Name: req.Name}, nil
	}}
	srv := NewDaemonServer(daemon, nil, nil)
	ctx := callerCtx()

	_, err := srv.CreateMission(ctx, &daemonpb.CreateMissionRequest{Name: "Scan", TargetId: "t", MissionDefinitionId: "d"})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Errorf("a mission named like a catalog mission: err = %v, want InvalidArgument", err)
	}
	_, err = srv.CreateMissionDefinition(ctx, &daemonpb.CreateMissionDefinitionRequest{Definition: &missionpb.MissionDefinition{Name: "scan"}})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Errorf("a definition named like a catalog mission: err = %v, want InvalidArgument", err)
	}

	_, err = srv.CreateMission(ctx, &daemonpb.CreateMissionRequest{
		Name: "mine", TargetId: "t", MissionDefinitionId: "d",
		Metadata: map[string]string{"catalog_mission": "scan", "owner": "alice"},
	})
	if err != nil {
		t.Fatalf("CreateMission: %v", err)
	}
	if _, forged := got.Metadata["catalog_mission"]; forged || got.Metadata["owner"] != "alice" {
		t.Errorf("metadata = %v, want the marker removed and the rest kept", got.Metadata)
	}
}

// A call with no verified identity is refused before the daemon is called.
func TestRunCatalogMission_RefusesACallerWithNoIdentity(t *testing.T) {
	t.Parallel()
	called := false
	srv := NewDaemonServer(&mockDaemon{runCatalogMissionFn: func(context.Context, RunCatalogMissionData) (string, error) {
		called = true
		return "m", nil
	}}, nil, nil)
	_, err := srv.RunCatalogMission(context.Background(), &daemonpb.RunCatalogMissionRequest{
		Name: "scan", TargetId: "t", Params: map[string]string{"imageRef": "r/i@sha256:abc"},
	})
	if status_grpc.Code(err) != codes.Unauthenticated || called {
		t.Errorf("err = %v, daemon called = %v, want Unauthenticated and no call", err, called)
	}
}

// placeholderParam is a value that renders and that a test uses when it cares
// about nothing else. The two durations of the fix-pass mission must be Go
// durations, because the mission derives its node timeout from them.
func placeholderParam(name string) string {
	if name == "codingTimeout" || name == "mergeWait" {
		return "40m"
	}
	return "v-" + name
}
